pub mod builtins;
pub mod engine;
pub mod eval;
pub mod memo;
pub mod resolve;
pub mod types;
pub mod walker;

use std::sync::Arc;

use async_trait::async_trait;
use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::{Entity, EntityUri};
#[cfg(test)]
use entity_hash::Hash;
use entity_handler::{
    Bounds, ExecuteOptions, Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST,
    STATUS_FORBIDDEN, STATUS_NOT_FOUND,
};
use entity_store::{ContentStore, LocationIndex};

use crate::eval::EvalContext;
use crate::types::*;

/// Unwrap a handler result into a ComputeValue.
///
/// compute/result entities are unwrapped to their inner value (the eval handler
/// wraps primitive results in compute/result{expression, value}).
/// compute/error entities are converted back to ComputeError.
/// All other entities are returned as ComputeValue::Entity.
///
/// Native-only: the dispatch bridge that consumes this is gated to non-WASM.
#[cfg(not(target_arch = "wasm32"))]
fn unwrap_handler_result(result: &HandlerResult) -> ComputeValue {
    if result.status >= 400 {
        if let Some(data) = decode_data(&result.result) {
            let code = data_str(&data, "code").unwrap_or_default();
            let message = data_str(&data, "message").unwrap_or_default();
            return ComputeError::InvalidExpression(format!("{}: {}", code, message)).to_value();
        }
        return ComputeError::InvalidExpression(format!(
            "Handler dispatch failed: status {}",
            result.status
        ))
        .to_value();
    }

    let entity = &result.result;
    if entity.entity_type == TYPE_RESULT {
        if let Some(data) = decode_data(entity) {
            if let Some(value) = data.get("value") {
                return ComputeValue::Primitive(value.clone());
            }
        }
    }
    if entity.entity_type == TYPE_ERROR {
        if let Some(data) = decode_data(entity) {
            let code = data_str(&data, "code").unwrap_or_default();
            let message = data_str(&data, "message").unwrap_or_default();
            return ComputeError::InvalidExpression(format!("{}: {}", code, message)).to_value();
        }
    }
    ComputeValue::Entity(entity.clone())
}

// ---------------------------------------------------------------------------
// ComputeHandler
// ---------------------------------------------------------------------------

pub struct ComputeHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
    engine: Option<Arc<engine::ComputeEngine>>,
}

impl ComputeHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/compute", local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
            engine: None,
        }
    }

    pub fn with_engine(mut self, engine: Arc<engine::ComputeEngine>) -> Self {
        self.engine = Some(engine);
        self
    }

    fn handle_eval(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // Path-as-resource (PROPOSAL-PATH-AS-RESOURCE-HYGIENE §3.1, P-COMPUTE-1):
        // the expression path is carried in resource, not params. Single-target
        // URI-only resource shape — anything else is 400 ambiguous_resource.
        let expression_uri = match ctx.resource_target.as_ref() {
            Some(rt) if rt.targets.len() == 1 && rt.exclude.is_empty() => rt.targets[0].clone(),
            _ => {
                let err = make_error_entity(
                    "ambiguous_resource",
                    "eval requires exactly one resource target (the expression path)",
                );
                return Ok(HandlerResult::error(STATUS_BAD_REQUEST, err));
            }
        };

        let params_data = decode_data(&ctx.params);

        // Resource targets are peer-qualified by dispatch (connection.rs); the
        // call below is idempotent so it works for both qualified and bare.
        let qualified = eval::qualify_path(&expression_uri, &self.local_peer_id);

        let hash = match self.location_index.get(&qualified) {
            Some(h) => h,
            None => {
                let err = make_error_entity("not_found", &format!("No entity at path: {}", expression_uri));
                return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
            }
        };

        let expression = match self.content_store.get(&hash) {
            Some(e) => e,
            None => {
                let err = make_error_entity("not_found", &format!("No entity at path: {}", expression_uri));
                return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
            }
        };

        // §4.7: Only compute expression types are valid eval targets
        if !is_compute_expression(&expression) {
            let err = make_error_entity(
                "invalid_expression",
                &format!("Entity at path is not a compute expression (type: {})", expression.entity_type),
            );
            return Ok(HandlerResult::error(STATUS_BAD_REQUEST, err));
        }

        let mut budget = init_budget(
            params_data.as_ref(),
            ctx.matching_grant.as_ref(),
            ctx.bounds.as_ref(),
        );

        let dispatch_execute = build_dispatch_execute(ctx, &self.local_peer_id, Arc::clone(&self.content_store));

        // Explicit eval (proposal §6.1): ctx.capability = caller's cap (the eval
        // authority), ctx.caller_capability = absent (the caller IS the source —
        // there is no separate external attribution to record).
        let mut eval_ctx = EvalContext::new(
            self.content_store.as_ref(),
            self.location_index.as_ref(),
            &ctx.included,
            &self.local_peer_id,
        )
        .with_capability(ctx.caller_capability.as_ref())
        .with_subgraph_root(Some(expression_uri.clone()))
        .with_dispatch_execute(dispatch_execute);

        let scope = Scope::new();
        let result = eval::evaluate(&expression, &scope, &mut budget, &mut eval_ctx);

        // PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE §3 (F10): an evaluated
        // compute/error is a *value*, not a dispatch failure. Return it at
        // status 200 as the result entity directly (the caller distinguishes
        // by `result.type == "compute/error"`); 4xx is reserved for dispatch /
        // transport / auth failures, which are emitted earlier in this handler.
        match &result {
            ComputeValue::Error(err) => Ok(HandlerResult::ok(err.to_entity())),
            _ => Ok(HandlerResult::ok(
                result.to_result_entity(&expression.content_hash),
            )),
        }
    }

    fn handle_install(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // §3.3: Installation requires a caller capability — it becomes the
        // installation grant that authorizes all reactive re-evaluation.
        // The capability may be available as a decoded token (caller_capability)
        // or as a raw entity in the included map (capability_hash + included).
        let (caller_cap, cap_entity_for_storage) = match ctx.caller_capability {
            Some(ref c) => {
                let entity = c.to_entity().expect("serialize capability");
                (c.clone(), Some(entity))
            }
            None => {
                // Capability not decoded, but may be in included map
                if let Some(cap_h) = ctx.capability_hash {
                    if let Some(raw) = ctx.included.get(&cap_h) {
                        match entity_capability::CapabilityToken::from_entity(raw) {
                            Ok(token) => (token, Some(raw.clone())),
                            Err(_) => {
                                let err = make_error_entity("permission_denied",
                                    "Install requires a valid caller capability (installation grant)");
                                return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
                            }
                        }
                    } else {
                        let err = make_error_entity("permission_denied",
                            "Install requires a caller capability (installation grant)");
                        return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
                    }
                } else {
                    let err = make_error_entity("permission_denied",
                        "Install requires a caller capability (installation grant)");
                    return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
                }
            }
        };

        // Path-as-resource (PROPOSAL-PATH-AS-RESOURCE-HYGIENE §3.1, P-COMPUTE-2):
        // the root expression path is carried in resource. result_path stays
        // in params — it's a handler-write target under the install grant, not
        // an authorization target the caller needs separate cover for.
        let qualified_resource = match ctx.resource_target.as_ref() {
            Some(rt) if rt.targets.len() == 1 && rt.exclude.is_empty() => rt.targets[0].clone(),
            _ => {
                let err = make_error_entity(
                    "ambiguous_resource",
                    "install requires exactly one resource target (the root expression path)",
                );
                return Ok(HandlerResult::error(STATUS_BAD_REQUEST, err));
            }
        };
        // Walker, dependency index, and stored subgraph metadata all expect a
        // bare path; resource arrives peer-qualified from dispatch, so strip
        // the prefix once here.
        let root_path = EntityUri::strip_peer_prefix(&qualified_resource).to_string();

        // Params is optional now — empty or absent means "no overrides".
        let params_data = decode_data(&ctx.params);

        let result_path = params_data
            .as_ref()
            .and_then(|d| data_str(d, "result_path"))
            .unwrap_or_else(|| format!("{}/result", root_path));

        let qualified_root = eval::qualify_path(&root_path, &self.local_peer_id);

        let hash = match self.location_index.get(&qualified_root) {
            Some(h) => h,
            None => {
                let err = make_error_entity("not_found", &format!("No expression at path: {}", root_path));
                return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
            }
        };

        let expression = match self.content_store.get(&hash) {
            Some(e) => e,
            None => {
                let err = make_error_entity("not_found", &format!("No expression at path: {}", root_path));
                return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
            }
        };

        if !is_compute_expression(&expression) {
            let err = make_error_entity("invalid_expression", "Entity at path is not a compute expression");
            return Ok(HandlerResult::error(STATUS_BAD_REQUEST, err));
        }

        // Phase 1: Audit subgraph
        let included = &ctx.included;
        let auditor = walker::audit_subgraph(
            &expression,
            self.content_store.as_ref(),
            included,
            Some(&root_path),
        );

        // F5 install-time enforcement (v3.10): static structural errors collected
        // by the walker (compute/apply with `capability` but no `resource`) are
        // category errors that fail before we audit capabilities.
        if let Some(msg) = auditor.structural_errors.first() {
            let err = make_error_entity("invalid_expression", msg);
            return Ok(HandlerResult::error(STATUS_BAD_REQUEST, err));
        }

        // CP1 (PROPOSAL-COHERENT-CAPABILITY-AUTHORITY): R1 chain-root check
        // on every static-literal `compute/apply.capability` reference, via
        // the unified primitive (V7 §5.5 check_creator_authority,
        // PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE).
        //
        // The installer's identity (EXECUTE author) MUST appear in each cap's
        // authority chain. Runs BEFORE F3 resource-coverage (proposal §6.1:
        // chain-root is cheaper and more fundamental). Dynamic capability
        // values fall through to runtime dual-check (F2). On success, each
        // cap's full chain is persisted to the local store (coherent-cap §2)
        // so reactive evaluation can resolve the literal cap by hash without
        // requiring re-delivery.
        if !auditor.static_literal_capabilities.is_empty() {
            let author = match ctx.author {
                Some(a) => a,
                None => {
                    let err = make_error_entity(
                        "missing_author",
                        "compute install requires authenticated author",
                    );
                    return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
                }
            };
            let cs = self.content_store.clone();
            let included_ref = &ctx.included;
            let mut chains_to_persist: Vec<Vec<Entity>> = Vec::new();
            for cap_hash in &auditor.static_literal_capabilities {
                let resolve = |h: &entity_hash::Hash| -> Option<Entity> {
                    included_ref.get(h).cloned().or_else(|| cs.get(h))
                };
                let auth_result =
                    match entity_protocol::check_creator_authority(cap_hash, &author, included_ref, resolve) {
                        Ok(r) => r,
                        Err(_) => {
                            let err = make_error_entity(
                                "chain_unreachable",
                                "compute/apply.capability authority chain has unreachable links",
                            );
                            return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
                        }
                    };
                if !auth_result.found {
                    let err = make_error_entity(
                        "embedded_cap_unauthorized",
                        "installer identity not in static compute/apply.capability chain",
                    );
                    return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
                }
                chains_to_persist.push(auth_result.chain);
            }
            // Persist only after every static-literal cap passed (proposal
            // §3.2: persistence on found=true; for CP1 we extend to "all
            // checks passed" since one install may carry multiple chains).
            for chain in chains_to_persist {
                for cap_entity in chain {
                    let _ = cs.put(cap_entity);
                }
            }
        }

        // Phase 2: Verify caller's capability covers all impure operations
        for path in &auditor.read_paths {
            if !entity_capability::check_permission(
                "get",
                &format!("/{}/system/tree", self.local_peer_id),
                &self.local_peer_id,
                Some(&entity_capability::ResourceTarget {
                    targets: vec![path.clone()],
                    exclude: vec![],
                }),
                &caller_cap,
                &self.local_peer_id,
            ) {
                let err = make_error_entity("permission_denied",
                    &format!("Capability does not cover read: {}", path));
                return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
            }
        }

        for target in &auditor.handler_targets {
            // F3 (v3.10): static literal resources audited at full resolution;
            // dynamic / absent resources fall back to handler+operation coverage
            // (target.resource = None — preserves prior behavior).
            if !entity_capability::check_permission(
                &target.operation,
                &format!("/{}/{}", self.local_peer_id, target.path),
                &self.local_peer_id,
                target.resource.as_ref(),
                &caller_cap,
                &self.local_peer_id,
            ) {
                let err = make_error_entity("permission_denied",
                    &format!("Capability does not cover handler: {}.{}", target.path, target.operation));
                return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
            }
        }

        if !entity_capability::check_permission(
            "put",
            &format!("/{}/system/tree", self.local_peer_id),
            &self.local_peer_id,
            Some(&entity_capability::ResourceTarget {
                targets: vec![result_path.clone()],
                exclude: vec![],
            }),
            &caller_cap,
            &self.local_peer_id,
        ) {
            let err = make_error_entity("permission_denied",
                &format!("Capability does not cover result write: {}", result_path));
            return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
        }

        for path in &auditor.write_paths {
            if !entity_capability::check_permission(
                "put",
                &format!("/{}/system/tree", self.local_peer_id),
                &self.local_peer_id,
                Some(&entity_capability::ResourceTarget {
                    targets: vec![path.clone()],
                    exclude: vec![],
                }),
                &caller_cap,
                &self.local_peer_id,
            ) {
                let err = make_error_entity("permission_denied",
                    &format!("Capability does not cover write: {}", path));
                return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
            }
        }

        // Phase 2b: Validate compute/lookup/hash data references (v3.7 D5)
        let mut authorized_data_hashes: Vec<Vec<u8>> = Vec::new();
        {
            for (hash, path_hint) in &auditor.data_hashes {
                if let Some(hint_path) = path_hint {
                    let qualified_hint = eval::qualify_path(hint_path, &self.local_peer_id);
                    let hint_hash = match self.location_index.get(&qualified_hint) {
                        Some(h) => h,
                        None => {
                            let err = make_error_entity("not_found",
                                &format!("No entity at hint path: {}", hint_path));
                            return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
                        }
                    };
                    if hint_hash != *hash {
                        let err = make_error_entity("hash_mismatch",
                            &format!("Entity at {} has different hash than expression references", hint_path));
                        return Ok(HandlerResult::error(STATUS_BAD_REQUEST, err));
                    }
                    if !entity_capability::check_permission(
                        "get",
                        &format!("/{}/system/tree", self.local_peer_id),
                        &self.local_peer_id,
                        Some(&entity_capability::ResourceTarget {
                            targets: vec![hint_path.clone()],
                            exclude: vec![],
                        }),
                        &caller_cap,
                        &self.local_peer_id,
                    ) {
                        let err = make_error_entity("permission_denied",
                            &format!("Caller grant does not cover tree GET at: {}", hint_path));
                        return Ok(HandlerResult::error(STATUS_FORBIDDEN, err));
                    }
                    authorized_data_hashes.push(hash.to_bytes().to_vec());
                } else {
                    let err = make_error_entity("no_authorization_path",
                        "compute/lookup/hash without path hint requires content_store_access");
                    return Ok(HandlerResult::error(STATUS_BAD_REQUEST, err));
                }
            }
        }

        // Phase 3: Create subgraph metadata
        let subgraph_id = walker::deterministic_id(&root_path);
        let subgraph_path = format!("system/compute/processes/{}", subgraph_id);

        let author = ctx.author.unwrap_or_else(|| entity_hash::Hash::compute("empty", b""));

        // Persist the installation grant to the content store so the reactive
        // engine can load it for §7.2 grant validation.
        let cap_hash = if let Some(entity) = cap_entity_for_storage {
            let h = entity.content_hash;
            let _ = self.content_store.put(entity);
            h
        } else {
            ctx.capability_hash.unwrap_or_else(|| entity_hash::Hash::compute("empty", b""))
        };

        let metadata_fields = vec![
            (Value::Text("authorized_data_hashes".into()),
             Value::Array(authorized_data_hashes.into_iter().map(Value::Bytes).collect())),
            (Value::Text("installation_grant".into()),
             Value::Bytes(cap_hash.to_bytes().to_vec())),
            (Value::Text("installed_by".into()),
             Value::Bytes(author.to_bytes().to_vec())),
            (Value::Text("result_path".into()),
             entity_ecf::text(&result_path)),
            (Value::Text("root_expression".into()),
             Value::Bytes(expression.content_hash.to_bytes().to_vec())),
            (Value::Text("root_expression_path".into()),
             entity_ecf::text(&root_path)),
            (Value::Text("status".into()),
             entity_ecf::text("active")),
        ];
        let metadata_data = Value::Map(metadata_fields);
        let metadata_entity = Entity::new(TYPE_SUBGRAPH, entity_ecf::to_ecf(&metadata_data))
            .expect("subgraph metadata entity");

        let metadata_hash = self.content_store.put(metadata_entity).expect("store metadata");
        let qualified_subgraph = eval::qualify_path(&subgraph_path, &self.local_peer_id);
        self.location_index.set(&qualified_subgraph, metadata_hash);

        // Phase 4: Register dependencies for reactive mode (§3.3)
        if let Some(ref engine) = self.engine {
            engine.register_subgraph_dependencies(&subgraph_path, &root_path, &expression);
        }

        // Return result
        let impure_data = entity_ecf::cbor_map! {
            "handler_targets" => Value::Array(auditor.handler_targets.iter().map(|t| {
                let mut fields = vec![
                    (Value::Text("operation".into()), entity_ecf::text(&t.operation)),
                    (Value::Text("path".into()), entity_ecf::text(&t.path)),
                ];
                if let Some(ref rt) = t.resource {
                    fields.push((
                        Value::Text("resource".into()),
                        Value::Map(vec![
                            (Value::Text("exclude".into()),
                             Value::Array(rt.exclude.iter().map(entity_ecf::text).collect())),
                            (Value::Text("targets".into()),
                             Value::Array(rt.targets.iter().map(entity_ecf::text).collect())),
                        ]),
                    ));
                }
                fields.sort_by(|(a, _), (b, _)| {
                    let ab = entity_ecf::to_ecf(a);
                    let bb = entity_ecf::to_ecf(b);
                    ab.len().cmp(&bb.len()).then(ab.cmp(&bb))
                });
                Value::Map(fields)
            }).collect()),
            "read_paths" => Value::Array(auditor.read_paths.iter().map(entity_ecf::text).collect()),
            "write_paths" => Value::Array(auditor.write_paths.iter().map(entity_ecf::text).collect())
        };

        let result_data = entity_ecf::cbor_map! {
            "impure_operations" => impure_data,
            "result_path" => entity_ecf::text(&result_path),
            "subgraph_path" => entity_ecf::text(&subgraph_path)
        };
        let result_entity = Entity::new("system/compute/install-result", entity_ecf::to_ecf(&result_data))
            .expect("install result");

        Ok(HandlerResult::ok(result_entity))
    }

    fn handle_uninstall(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // Path-as-resource (PROPOSAL-PATH-AS-RESOURCE-HYGIENE §3.1, P-COMPUTE-3):
        // the subgraph path is carried in resource; the
        // `system/compute/uninstall-request` wrapper is eliminated. Params is
        // the empty-params shape (`primitive/any` with `a0` data) — decoded
        // but unused.
        let qualified_resource = match ctx.resource_target.as_ref() {
            Some(rt) if rt.targets.len() == 1 && rt.exclude.is_empty() => rt.targets[0].clone(),
            _ => {
                let err = make_error_entity(
                    "ambiguous_resource",
                    "uninstall requires exactly one resource target (the subgraph path)",
                );
                return Ok(HandlerResult::error(STATUS_BAD_REQUEST, err));
            }
        };
        let subgraph_path = EntityUri::strip_peer_prefix(&qualified_resource).to_string();

        let qualified = eval::qualify_path(&subgraph_path, &self.local_peer_id);
        let hash = match self.location_index.get(&qualified) {
            Some(h) => h,
            None => {
                let err = make_error_entity("not_found", "No installed subgraph at path");
                return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
            }
        };

        let subgraph = match self.content_store.get(&hash) {
            Some(e) => e,
            None => {
                let err = make_error_entity("not_found", "No installed subgraph at path");
                return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
            }
        };

        if subgraph.entity_type != TYPE_SUBGRAPH {
            let err = make_error_entity("not_found", "Entity at path is not a subgraph");
            return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
        }

        // Remove dependency registrations (§3.4)
        if let Some(ref engine) = self.engine {
            engine.dependency_index.remove_subgraph(&subgraph_path);
        }

        self.location_index.remove(&qualified);

        let status_data = entity_ecf::cbor_map! {
            "status" => entity_ecf::integer(200)
        };
        let status_entity = Entity::new("system/protocol/status", entity_ecf::to_ecf(&status_data))
            .expect("status entity");
        Ok(HandlerResult::ok(status_entity))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for ComputeHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "eval" => self.handle_eval(ctx),
            "install" => self.handle_install(ctx),
            "uninstall" => self.handle_uninstall(ctx),
            other => {
                let err = make_error_entity(
                    "unknown_operation",
                    &format!("Unknown operation: {}", other),
                );
                Ok(HandlerResult::error(STATUS_BAD_REQUEST, err))
            }
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "compute"
    }

    fn operations(&self) -> &[&str] {
        &["eval", "install", "uninstall"]
    }
}

// ---------------------------------------------------------------------------
// Entity-native handler dispatch (V7 §6.6 / PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH)
// ---------------------------------------------------------------------------

/// Run entity-native dispatch for a handler whose manifest carries `expression_path`.
///
/// Per V7 §6.6:
///   1. Caller already verified handler grant exists and is non-empty (§7.1).
///   2. Loads expression at `expression_path` (404 if missing).
///   3. Builds scope `{operation, params, resource, caller_capability}` from the
///      request context (E1).
///   4. Sets `ctx.capability = handler_grant`, `ctx.caller_capability = caller's cap`,
///      `ctx.subgraph_root = expression_path` (E2 + relative-path resolution).
///   5. Invokes `evaluate()` with the prepared context.
///   6. Unwraps the result to a `HandlerResult` (E3) — `compute/error` → 400,
///      bare primitives wrapped at the dispatch boundary using the operation's
///      declared `output_type` (defaults to `primitive/any`), entities pass
///      through as-is.
///
/// `output_type` is the declared output type for `ctx.operation` from the
/// handler's interface entity (`system/handler/{pattern}.operations[op].output_type`).
/// Pass `None` to default to `primitive/any` for primitive wrapping.
///
/// Returns `Ok(HandlerResult)` for any outcome representable as a handler response;
/// `Err(HandlerError)` only for infrastructure failures (entity not loadable, etc.).
pub fn dispatch_entity_native(
    expression_path: &str,
    handler_grant: &entity_capability::CapabilityToken,
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: &str,
    ctx: &HandlerContext,
    output_type: Option<&str>,
) -> Result<HandlerResult, HandlerError> {
    let qualified_expr = eval::qualify_path(expression_path, local_peer_id);
    let expr_hash = match location_index.get(&qualified_expr) {
        Some(h) => h,
        None => {
            let err = make_error_entity(
                "handler_expression_missing",
                &format!("No expression at expression_path: {}", expression_path),
            );
            return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
        }
    };
    let expression = match content_store.get(&expr_hash) {
        Some(e) => e,
        None => {
            let err = make_error_entity(
                "handler_expression_missing",
                &format!("Expression entity missing in content store: {}", expression_path),
            );
            return Ok(HandlerResult::error(STATUS_NOT_FOUND, err));
        }
    };
    if !is_compute_expression(&expression) {
        let err = make_error_entity(
            "invalid_expression",
            &format!(
                "Entity at expression_path is not a compute expression (type: {})",
                expression.entity_type
            ),
        );
        return Ok(HandlerResult::error(STATUS_BAD_REQUEST, err));
    }

    // E1: pre-populate scope with the four request-context bindings.
    let mut scope = Scope::new();
    scope.set(
        "operation".to_string(),
        ComputeValue::Primitive(Value::Text(ctx.operation.clone())),
    );
    scope.set(
        "params".to_string(),
        ComputeValue::Entity(ctx.params.clone()),
    );
    scope.set(
        "resource".to_string(),
        match &ctx.resource_target {
            Some(rt) => ComputeValue::Entity(resource_target_to_entity(rt)),
            None => ComputeValue::Primitive(Value::Null),
        },
    );
    scope.set(
        "caller_capability".to_string(),
        match ctx.caller_capability.as_ref().and_then(|c| c.to_entity().ok()) {
            Some(e) => ComputeValue::Entity(e),
            None => ComputeValue::Primitive(Value::Null),
        },
    );

    // §7.1 verified by the caller; budget is constrained by the handler grant
    // (its compute constraints, if any) plus request bounds.
    let mut budget = init_budget(
        None,
        ctx.matching_grant.as_ref(),
        ctx.bounds.as_ref(),
    );

    let dispatch_execute = build_dispatch_execute(ctx, local_peer_id, Arc::clone(&content_store));

    // E2: ctx.capability = handler_grant; ctx.caller_capability = caller's cap.
    let mut eval_ctx = EvalContext::new(
        content_store.as_ref(),
        location_index.as_ref(),
        &ctx.included,
        local_peer_id,
    )
    .with_capability(Some(handler_grant))
    .with_caller_capability(ctx.caller_capability.as_ref())
    .with_subgraph_root(Some(expression_path.to_string()))
    .with_dispatch_execute(dispatch_execute);

    let result = eval::evaluate(&expression, &scope, &mut budget, &mut eval_ctx);

    Ok(unwrap_native_dispatch_result(result, output_type))
}

/// Convert a ResourceTarget into a `system/protocol/resource-target` entity for
/// scope binding.
fn resource_target_to_entity(rt: &entity_capability::ResourceTarget) -> Entity {
    let data = entity_ecf::cbor_map! {
        "exclude" => Value::Array(rt.exclude.iter().map(entity_ecf::text).collect()),
        "targets" => Value::Array(rt.targets.iter().map(entity_ecf::text).collect())
    };
    Entity::new("system/protocol/resource-target", entity_ecf::to_ecf(&data))
        .expect("resource target entity")
}

/// Unwrap a ComputeValue into a HandlerResult per PROPOSAL §4 (E3, revised) and
/// PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE §3 (F10).
///
/// The dispatch boundary unwraps `compute/result` and `compute/error`; everything
/// else passes through. Bare primitives are wrapped at the boundary using the
/// operation's declared `output_type` (defaults to `primitive/any` when absent
/// or empty) so the wire response is always a typed entity.
///
///   compute/error → 200, error-as-value (caller detects via `result.type`)
///   compute/result → 200, unwrap to inner value (entity or wrapped primitive)
///   any other entity → 200, pass-through
///   primitive → 200, wrapped as `{type: output_type, data: <cbor of primitive>}`
///   closure → 400 (closures have no wire representation; expression author error)
fn unwrap_native_dispatch_result(
    value: ComputeValue,
    output_type: Option<&str>,
) -> HandlerResult {
    match value {
        ComputeValue::Error(err) => HandlerResult::ok(err.to_entity()),
        ComputeValue::Entity(e) => {
            if e.entity_type == TYPE_ERROR {
                HandlerResult::ok(e)
            } else if e.entity_type == TYPE_RESULT {
                // compute/result wrapper from explicit eval — unwrap data.value.
                // If the value is an inline entity reference we pass through; if
                // primitive, re-wrap with the operation's output_type per spec.
                unwrap_compute_result_entity(&e, output_type)
            } else {
                HandlerResult::ok(e)
            }
        }
        ComputeValue::Primitive(p) => HandlerResult::ok(wrap_primitive(p, output_type)),
        ComputeValue::Uint(u) => HandlerResult::ok(wrap_primitive(
            Value::Integer(ciborium::value::Integer::from(u)),
            output_type,
        )),
        ComputeValue::Closure(_) => {
            let err = make_error_entity(
                "invalid_expression",
                "Entity-native handler returned a closure — closures have no wire representation",
            );
            HandlerResult::error(STATUS_BAD_REQUEST, err)
        }
    }
}

/// Wrap a CBOR primitive value into an entity using the declared `output_type`,
/// or `primitive/any` when none is declared. The data field is the canonical
/// ECF encoding of the primitive value itself — no `{value: …}` nesting.
fn wrap_primitive(value: Value, output_type: Option<&str>) -> Entity {
    let entity_type = output_type
        .filter(|s| !s.is_empty())
        .unwrap_or("primitive/any");
    let data = entity_ecf::to_ecf(&value);
    Entity::new(entity_type, data).expect("wrap primitive entity")
}

/// Unwrap a `compute/result` entity at the dispatch boundary. The wrapper
/// carries `value` as a CBOR field — could be a primitive or an entity hash
/// reference. We surface the inner value as a wrapped entity using the
/// operation's `output_type`.
fn unwrap_compute_result_entity(entity: &Entity, output_type: Option<&str>) -> HandlerResult {
    let data = match decode_data(entity) {
        Some(d) => d,
        None => return HandlerResult::ok(entity.clone()),
    };
    let value = match data.get("value") {
        Some(v) => v.clone(),
        None => return HandlerResult::ok(entity.clone()),
    };
    HandlerResult::ok(wrap_primitive(value, output_type))
}

/// Read `expression_path` from a `system/handler` manifest entity, if present.
///
/// Returns `None` for non-handler entities, missing field, or decode failure.
/// Caller is responsible for verifying the handler grant exists (§7.1) before
/// invoking `dispatch_entity_native`.
pub fn extract_expression_path(handler_entity: &Entity) -> Option<String> {
    if handler_entity.entity_type != "system/handler" {
        return None;
    }
    let data = decode_data(handler_entity)?;
    data_str(&data, "expression_path")
}

// ---------------------------------------------------------------------------
// Budget initialization (§5.2)
// ---------------------------------------------------------------------------

pub fn init_budget(
    params_data: Option<&Value>,
    matching_grant: Option<&entity_capability::GrantEntry>,
    bounds: Option<&Bounds>,
) -> Budget {
    let request_budget = params_data
        .and_then(|d| d.get("budget"))
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);

    let bounds_budget = bounds
        .and_then(|b| b.budget)
        .unwrap_or(PEER_DEFAULT_MAX_OPS);

    let (cap_ops, cap_depth) = extract_compute_constraints(matching_grant);

    let operations = request_budget.min(bounds_budget).min(cap_ops);

    Budget::new(operations, cap_depth)
}

fn extract_compute_constraints(
    grant: Option<&entity_capability::GrantEntry>,
) -> (u64, u64) {
    let grant = match grant {
        Some(g) => g,
        None => return (PEER_DEFAULT_MAX_OPS, PEER_DEFAULT_MAX_DEPTH),
    };

    let constraints = match &grant.constraints {
        Some(c) => c,
        None => return (PEER_DEFAULT_MAX_OPS, PEER_DEFAULT_MAX_DEPTH),
    };

    let compute = match constraints.get("system/compute") {
        Some(c) => c,
        None => return (PEER_DEFAULT_MAX_OPS, PEER_DEFAULT_MAX_DEPTH),
    };

    let ops = compute
        .get("max_compute_operations")
        .and_then(|v| v.as_u64())
        .unwrap_or(PEER_DEFAULT_MAX_OPS);

    let depth = compute
        .get("max_compute_depth")
        .and_then(|v| v.as_u64())
        .unwrap_or(PEER_DEFAULT_MAX_DEPTH);

    (ops, depth)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a dispatch callback from the handler context's execute_fn.
///
/// On native, uses `block_in_place` + `block_on` to bridge async → sync.
/// Returns None if execute_fn is not available (e.g. WASM or no dispatch wired).
///
/// `content_store` is the local content store where included entities from
/// a returned `HandlerResult` get written so that compute's downstream
/// navigation (which resolves hashes through the content store) can see
/// them — PROPOSAL-CROSS-IMPL-STANDARDIZATION-CATCHUP §2 dispatch-surface
/// result-equivalence.
fn build_dispatch_execute<'a>(
    ctx: &'a HandlerContext,
    local_peer_id: &'a str,
    content_store: Arc<dyn ContentStore>,
) -> Option<eval::DispatchExecuteFn<'a>> {
    let exec_fn = ctx.execute_fn.as_ref()?;
    let exec_fn = Arc::clone(exec_fn);
    let default_cap_entity = ctx
        .caller_capability
        .as_ref()
        .and_then(|c| c.to_entity().ok());
    let local_peer_id = local_peer_id.to_string();

    let dispatch = move |path: &str,
                         operation: &str,
                         resource: Option<entity_capability::ResourceTarget>,
                         params: Entity,
                         cap_override: Option<Entity>|
          -> ComputeValue {
        let qualified_path = eval::qualify_path(path, &local_peer_id);
        // §6.6 / proposal §3.2: when compute/apply provides a capability field,
        // the dual-check has already passed at the eval call site — dispatch with
        // the provided capability. Otherwise fall back to ctx.capability (which
        // for explicit eval is the caller's cap).
        let dispatch_cap = cap_override.or_else(|| default_cap_entity.clone());
        // F4 (v3.10): the constructed EXECUTE's `resource` field is set from the
        // resolved compute/apply.resource. When absent, the EXECUTE has no
        // resource field and the dispatch chain falls back to handler+operation
        // coverage only (V7 §5.2 — null resource skips the resource dimension).
        let options = ExecuteOptions {
            resource,
            capability: dispatch_cap,
            ..Default::default()
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            let result = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on((exec_fn)(
                    qualified_path,
                    operation.to_string(),
                    params,
                    options,
                ))
            });
            match result {
                Ok(handler_result) => {
                    // PROPOSAL-CROSS-IMPL-STANDARDIZATION-CATCHUP §2: when a
                    // dispatched handler returns a `system/envelope` result
                    // (or any shape that bundles supporting entities), the
                    // `result.included` map carries them. Without absorbing
                    // those into the content store here, compute's downstream
                    // navigation (e.g., walking a returned trie root's
                    // children) would fail to resolve the hashes because the
                    // entities are nowhere in the local resolution path —
                    // the silent subtree-lost shape Python found and the
                    // proposal §2 pins as a load-bearing invariant. Writes
                    // are content-addressed, so duplicates are no-ops.
                    for (_h, entity) in handler_result.included.iter() {
                        let _ = content_store.put(entity.clone());
                    }
                    unwrap_handler_result(&handler_result)
                }
                Err(e) => ComputeError::InvalidExpression(format!(
                    "Handler dispatch error: {}",
                    e
                ))
                .to_value(),
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = (qualified_path, options, params, operation, &exec_fn);
            let _ = &content_store;
            ComputeError::InvalidExpression(
                "Handler dispatch not available in WASM context".into(),
            )
            .to_value()
        }
    };

    Some(Box::new(dispatch))
}

/// Build a `system/protocol/error` entity carrying `code` and `message`
/// for a **transport-level** dispatch failure (4xx/5xx).
///
/// Every caller pairs this with `HandlerResult::error(STATUS_*, …)`: a
/// missing path, ambiguous resource, type-check failure, or auth refusal —
/// i.e. the handler could not produce a value. Per
/// PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE §3 (F10), these are
/// dispatch/transport/auth failures, distinct from an *evaluated*
/// `compute/error` VALUE (surfaced at status 200 via
/// [`ComputeError::to_entity`]). Transport failures therefore carry the
/// substrate's canonical `system/protocol/error` body so callers' status
/// mapping (`SdkError::from_handler_result`, `unwrap_handler_result`) can
/// extract `code` uniformly — matching the Go reference, which uses
/// `handler.NewErrorResponse` (→ `system/protocol/error`) at the same sites.
fn make_error_entity(code: &str, message: &str) -> Entity {
    entity_handler::error_entity(code, message)
}

// ---------------------------------------------------------------------------
// Entity-native dispatch tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod entity_native_tests {
    use super::*;
    use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};
    use std::collections::HashMap;

    const TEST_PID: &str = "testpeer123456789012345678901234567890123456";

    fn wildcard_grant() -> entity_capability::CapabilityToken {
        entity_capability::CapabilityToken {
            grants: entity_capability::wildcard_handler_grant(),
            granter: entity_capability::Granter::Single(Hash::compute("test", b"granter")),
            grantee: Hash::compute("test", b"grantee"),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        }
    }

    fn make_handler_entity(expression_path: Option<&str>) -> Entity {
        let mut fields = vec![
            (
                Value::Text("interface".into()),
                entity_ecf::text("system/handler/app/echo"),
            ),
        ];
        if let Some(p) = expression_path {
            fields.push((Value::Text("expression_path".into()), entity_ecf::text(p)));
        }
        fields.sort_by(|(a, _), (b, _)| {
            let ab = entity_ecf::to_ecf(a);
            let bb = entity_ecf::to_ecf(b);
            ab.len().cmp(&bb.len()).then(ab.cmp(&bb))
        });
        Entity::new("system/handler", entity_ecf::to_ecf(&Value::Map(fields))).unwrap()
    }

    #[test]
    fn test_extract_expression_path_present() {
        let h = make_handler_entity(Some("app/echo/expr"));
        assert_eq!(extract_expression_path(&h), Some("app/echo/expr".to_string()));
    }

    #[test]
    fn test_extract_expression_path_absent() {
        let h = make_handler_entity(None);
        assert_eq!(extract_expression_path(&h), None);
    }

    #[test]
    fn test_extract_expression_path_wrong_type() {
        let data = entity_ecf::cbor_map! {
            "expression_path" => entity_ecf::text("app/foo")
        };
        let e = Entity::new("system/handler/interface", entity_ecf::to_ecf(&data)).unwrap();
        assert_eq!(extract_expression_path(&e), None);
    }

    fn make_handler_context(operation: &str) -> HandlerContext {
        // Minimal HandlerContext for entity-native dispatch tests.
        let exec_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "operation" => entity_ecf::text(operation),
            "uri" => entity_ecf::text("entity://test/app/echo")
        });
        let execute = Entity::new("system/protocol/execute", exec_data).unwrap();
        let params_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "message" => entity_ecf::text("hello")
        });
        let params = Entity::new("primitive/map", params_data).unwrap();

        HandlerContext {
            handler_grant: Some(wildcard_grant()),
            caller_capability: Some(wildcard_grant()),
            execute,
            params,
            pattern: format!("/{}/app/echo", TEST_PID),
            suffix: String::new(),
            resource_target: None,
            author: Some(Hash::compute("test", b"author")),
            session_peer_id: None,
            request_id: "test-req".to_string(),
            operation: operation.to_string(),
            execute_fn: None,
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: Some(Hash::compute("test", b"cap")),
            handler_grant_hash: Some(Hash::compute("test", b"hgrant")),
            bounds: None,
            is_external: false,
        }
    }

    #[test]
    fn test_dispatch_entity_native_construct_returns_typed_entity() {
        // Expression: construct{entity_type: "app/echo/result", fields: {echoed: lookup/scope("operation")}}
        // Entity-native dispatch should run it under the handler grant and return the constructed entity.
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());

        // lookup/scope("operation")
        let scope_lookup_data = entity_ecf::cbor_map! {
            "name" => entity_ecf::text("operation")
        };
        let scope_lookup =
            Entity::new(TYPE_LOOKUP_SCOPE, entity_ecf::to_ecf(&scope_lookup_data)).unwrap();
        let scope_lookup_h = cs.put(scope_lookup).unwrap();

        // construct{entity_type: "app/echo/result", fields: {echoed: <scope_lookup_h>}}
        let construct_data = entity_ecf::cbor_map! {
            "entity_type" => entity_ecf::text("app/echo/result"),
            "fields" => Value::Map(vec![
                (Value::Text("echoed".into()), Value::Bytes(scope_lookup_h.to_bytes().to_vec())),
            ])
        };
        let construct = Entity::new(TYPE_CONSTRUCT, entity_ecf::to_ecf(&construct_data)).unwrap();
        let construct_h = cs.put(construct).unwrap();

        // Bind expression at app/echo/expr
        li.set(&format!("/{}/app/echo/expr", TEST_PID), construct_h);

        let grant = wildcard_grant();
        let ctx = make_handler_context("run");

        let result = dispatch_entity_native(
            "app/echo/expr",
            &grant,
            cs.clone(),
            li.clone(),
            TEST_PID,
            &ctx,
            None,
        )
        .expect("dispatch ok");

        assert_eq!(result.status, 200);
        assert_eq!(result.result.entity_type, "app/echo/result");

        // Decode and verify the echoed field carries the operation name.
        // v3.19c α (revised): a compute-constructed entity's data
        // is bare per V7 §1.4 — same shape as a hand-built entity. The
        // echoed field is the bare CBOR text value "run".
        let data: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).expect("decode result");
        let echoed = data.get("echoed").and_then(|v| v.as_text()).unwrap();
        assert_eq!(echoed, "run");
    }

    #[test]
    fn test_dispatch_entity_native_missing_expression_returns_404() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let grant = wildcard_grant();
        let ctx = make_handler_context("run");

        let result =
            dispatch_entity_native("app/echo/missing", &grant, cs, li, TEST_PID, &ctx, None)
                .expect("dispatch ok");
        assert_eq!(result.status, STATUS_NOT_FOUND);
        // Transport failure → substrate `system/protocol/error` (not the
        // `compute/error` value type), so callers extract `code` uniformly.
        let (code, _) = entity_handler::decode_error_entity(&result.result)
            .expect("transport error decodes as system/protocol/error");
        assert_eq!(code.as_deref(), Some("handler_expression_missing"));
    }

    #[test]
    fn test_dispatch_entity_native_non_compute_expression_returns_400() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());

        let not_compute = Entity::new(
            "app/foo",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! { "x" => entity_ecf::integer(1) }),
        )
        .unwrap();
        let h = cs.put(not_compute).unwrap();
        li.set(&format!("/{}/app/echo/expr", TEST_PID), h);

        let grant = wildcard_grant();
        let ctx = make_handler_context("run");

        let result =
            dispatch_entity_native("app/echo/expr", &grant, cs, li, TEST_PID, &ctx, None)
                .expect("dispatch ok");
        assert_eq!(result.status, STATUS_BAD_REQUEST);
        // Transport failure → substrate `system/protocol/error` (not the
        // `compute/error` value type), so callers extract `code` uniformly.
        let (code, _) = entity_handler::decode_error_entity(&result.result)
            .expect("transport error decodes as system/protocol/error");
        assert_eq!(code.as_deref(), Some("invalid_expression"));
    }

    #[test]
    fn test_dispatch_entity_native_primitive_result_wraps_with_output_type() {
        // PROPOSAL §4 (revised): bare-primitive results are wrapped at the
        // dispatch boundary using the operation's declared output_type.
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());

        let lit_data = entity_ecf::cbor_map! { "value" => entity_ecf::integer(42) };
        let lit = Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&lit_data)).unwrap();
        let h = cs.put(lit).unwrap();
        li.set(&format!("/{}/app/echo/expr", TEST_PID), h);

        let grant = wildcard_grant();
        let ctx = make_handler_context("run");

        let result = dispatch_entity_native(
            "app/echo/expr",
            &grant,
            cs,
            li,
            TEST_PID,
            &ctx,
            Some("primitive/integer"),
        )
        .expect("dispatch ok");
        assert_eq!(result.status, 200);
        assert_eq!(result.result.entity_type, "primitive/integer");
        let v: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).expect("decode primitive");
        assert_eq!(v.as_integer().map(|i| i128::from(i) as i64), Some(42));
    }

    #[test]
    fn test_dispatch_entity_native_primitive_result_defaults_to_primitive_any() {
        // PROPOSAL §4: when output_type is absent, default to primitive/any.
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());

        let lit_data = entity_ecf::cbor_map! { "value" => entity_ecf::text("hello") };
        let lit = Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&lit_data)).unwrap();
        let h = cs.put(lit).unwrap();
        li.set(&format!("/{}/app/echo/expr", TEST_PID), h);

        let grant = wildcard_grant();
        let ctx = make_handler_context("run");

        let result =
            dispatch_entity_native("app/echo/expr", &grant, cs, li, TEST_PID, &ctx, None)
                .expect("dispatch ok");
        assert_eq!(result.status, 200);
        assert_eq!(result.result.entity_type, "primitive/any");
        let v: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).expect("decode primitive");
        assert_eq!(v.as_text(), Some("hello"));
    }

    /// PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE §3 (F10): explicit `eval`
    /// must also surface an evaluated `compute/error` at status 200 (as the bare
    /// `compute/error` entity, not wrapped in `compute/result`) — the caller
    /// reads `result.type == "compute/error"` and propagates.
    #[test]
    fn test_handle_eval_evaluated_error_returns_200_with_compute_error() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());

        let arr_data = entity_ecf::cbor_map! {
            "value" => Value::Array(vec![entity_ecf::integer(1)])
        };
        let arr_h = cs.put(Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&arr_data)).unwrap()).unwrap();
        let idx_data = entity_ecf::cbor_map! { "value" => entity_ecf::integer(-1) };
        let idx_h = cs.put(Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&idx_data)).unwrap()).unwrap();
        let index_data = entity_ecf::cbor_map! {
            "array" => Value::Bytes(arr_h.to_bytes().to_vec()),
            "index" => Value::Bytes(idx_h.to_bytes().to_vec())
        };
        let index_h = cs.put(Entity::new(TYPE_INDEX, entity_ecf::to_ecf(&index_data)).unwrap()).unwrap();

        let expr_path = format!("/{}/app/work/expr", TEST_PID);
        li.set(&expr_path, index_h);

        let handler = ComputeHandler::new(cs.clone(), li.clone(), TEST_PID.to_string());
        let mut ctx = make_handler_context("eval");
        ctx.resource_target = Some(entity_capability::ResourceTarget {
            targets: vec!["app/work/expr".to_string()],
            exclude: vec![],
        });

        let result = handler.handle_eval(&ctx).expect("handle_eval ok");
        assert_eq!(result.status, 200, "evaluated compute/error must surface at 200");
        assert_eq!(result.result.entity_type, TYPE_ERROR);
        let data: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).expect("decode error");
        assert_eq!(
            data_str(&data, "code").as_deref(),
            Some("index_out_of_range")
        );
    }

    /// PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE §3 (F10): an evaluated
    /// `compute/error` is a value, not a dispatch failure. Entity-native dispatch
    /// must surface it at **status 200** with the `compute/error` entity as the
    /// result body so a caller can read `result.type == "compute/error"` and
    /// propagate it NaN-style. 4xx is reserved for dispatch/transport/auth
    /// failures (handler missing, malformed request, etc.).
    #[test]
    fn test_dispatch_entity_native_evaluated_error_returns_200_with_compute_error() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());

        // compute/index over a 1-element literal array with index = -1 →
        // ComputeError::IndexOutOfRange (negative index, eval/construct.rs).
        let arr_data = entity_ecf::cbor_map! {
            "value" => Value::Array(vec![entity_ecf::integer(1)])
        };
        let arr_lit = Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&arr_data)).unwrap();
        let arr_h = cs.put(arr_lit).unwrap();

        let idx_data = entity_ecf::cbor_map! { "value" => entity_ecf::integer(-1) };
        let idx_lit = Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&idx_data)).unwrap();
        let idx_h = cs.put(idx_lit).unwrap();

        let index_data = entity_ecf::cbor_map! {
            "array" => Value::Bytes(arr_h.to_bytes().to_vec()),
            "index" => Value::Bytes(idx_h.to_bytes().to_vec())
        };
        let index_expr = Entity::new(TYPE_INDEX, entity_ecf::to_ecf(&index_data)).unwrap();
        let index_h = cs.put(index_expr).unwrap();
        li.set(&format!("/{}/app/echo/expr", TEST_PID), index_h);

        let grant = wildcard_grant();
        let ctx = make_handler_context("run");

        let result =
            dispatch_entity_native("app/echo/expr", &grant, cs, li, TEST_PID, &ctx, None)
                .expect("dispatch ok");
        assert_eq!(result.status, 200, "evaluated compute/error must surface at 200");
        assert_eq!(result.result.entity_type, TYPE_ERROR);
        let data: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).expect("decode error");
        assert_eq!(
            data_str(&data, "code").as_deref(),
            Some("index_out_of_range")
        );
    }

    /// EXTENSION-COMPUTE v3.19c §3.2 (spec body merged): an
    /// **impure-op `permission_denied` during eval** surfaces at status **200**
    /// with a `compute/error{code:"permission_denied"}` body — exactly like
    /// any other propagated error value (§1.5 / F10). 4xx is reserved for
    /// authorization of the request itself (the eval EXECUTE unauthorized
    /// before evaluation, install pre-audit rejecting an under-capable
    /// subgraph). This locks in the residual ruling — pre-flight-403-vs-
    /// runtime-200 split keyed on static-determinability would be impl-
    /// dependent, exactly the divergence class this arc closed.
    ///
    /// Exercises the path with `compute/lookup/tree` on a path the supplied
    /// capability does NOT cover — eval-time denial → `200 + compute/error`.
    #[test]
    fn test_v319c_3_2_impure_op_permission_denied_during_eval_returns_200() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());

        // A target entity at a path the capability will NOT cover.
        let target = Entity::new(
            "app/data",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! { "x" => entity_ecf::integer(1) }),
        )
        .unwrap();
        let target_h = cs.put(target).unwrap();
        li.set(&format!("/{}/restricted/path", TEST_PID), target_h);

        // compute/lookup/tree("restricted/path")
        let lookup_data = entity_ecf::cbor_map! {
            "path" => entity_ecf::text("restricted/path")
        };
        let lookup = Entity::new("compute/lookup/tree", entity_ecf::to_ecf(&lookup_data)).unwrap();
        let lookup_h = cs.put(lookup).unwrap();

        let expr_path = format!("/{}/app/work/restricted-eval", TEST_PID);
        li.set(&expr_path, lookup_h);

        // Narrow capability: covers compute/eval on the expression but NOT
        // tree:get on "restricted/path" — eval-time check fails.
        let narrow_cap = entity_capability::CapabilityToken {
            grants: vec![entity_capability::GrantEntry {
                handlers: entity_capability::PathScope::new(vec!["system/compute".into()]),
                resources: entity_capability::PathScope::new(vec![
                    "app/work/restricted-eval".into(),
                ]),
                operations: entity_capability::IdScope::new(vec!["eval".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }],
            granter: entity_capability::Granter::Single(Hash::compute("test", b"narrow")),
            grantee: Hash::compute("test", b"grantee"),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };

        let handler = ComputeHandler::new(cs.clone(), li.clone(), TEST_PID.to_string());
        let mut ctx = make_handler_context("eval");
        ctx.resource_target = Some(entity_capability::ResourceTarget {
            targets: vec!["app/work/restricted-eval".to_string()],
            exclude: vec![],
        });
        ctx.caller_capability = Some(narrow_cap);

        let result = handler.handle_eval(&ctx).expect("handle_eval ok");
        assert_eq!(
            result.status, 200,
            "impure-op permission_denied during eval MUST surface at 200 \
             (v3.19c §3.2 — eval-time denial is an error value, not 4xx)"
        );
        assert_eq!(result.result.entity_type, TYPE_ERROR);
        let data: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).expect("decode error");
        assert_eq!(
            data_str(&data, "code").as_deref(),
            Some("permission_denied"),
            "the surfaced error must be compute/error{{code:\"permission_denied\"}}"
        );
    }

    /// PROPOSAL-CROSS-IMPL-STANDARDIZATION-CATCHUP §2 regression. When
    /// compute dispatches a handler internally and the handler returns a
    /// HandlerResult with `included` entities (the `system/envelope` shape),
    /// those entities MUST be threaded through so subsequent navigation can
    /// resolve them. Pre-fix Rust dropped them at the dispatch bridge,
    /// matching the Python lossy-internal-dispatch finding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[cfg(not(target_arch = "wasm32"))]
    async fn test_dispatch_preserves_handler_result_included() {
        use entity_handler::HandlerResult;
        use std::sync::Arc;

        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());

        // Two entities that a hypothetical subtree-returning handler bundles
        // in `included` (e.g., trie nodes from `tree:snapshot`). They are
        // NOT pre-loaded into the local content store — they only flow
        // through dispatch.
        let inner_a = Entity::new("test/leaf", entity_ecf::to_ecf(&entity_ecf::text("a"))).unwrap();
        let inner_b = Entity::new("test/leaf", entity_ecf::to_ecf(&entity_ecf::text("b"))).unwrap();
        let hash_a = inner_a.content_hash;
        let hash_b = inner_b.content_hash;

        // Sanity: the entities are NOT in the store yet — without the fix,
        // navigation pointing at hash_a/hash_b after dispatch would fail.
        assert!(cs.get(&hash_a).is_none());
        assert!(cs.get(&hash_b).is_none());

        // Mock exec_fn that returns a HandlerResult bundling both entities
        // in `included` (no envelope wrapping needed for this test — the
        // observable property is "did dispatch absorb the bundle"). The
        // closure rebuilds the result each invocation because HandlerResult
        // isn't Clone — we capture the inputs that ARE cloneable.
        let inner_a_cap = inner_a.clone();
        let inner_b_cap = inner_b.clone();
        let exec_fn: entity_handler::ExecuteFn = Arc::new(move |_path, _op, _params, _opts| {
            let inner_a = inner_a_cap.clone();
            let inner_b = inner_b_cap.clone();
            Box::pin(async move {
                let mut included = std::collections::HashMap::new();
                included.insert(inner_a.content_hash, inner_a);
                included.insert(inner_b.content_hash, inner_b);
                let root_result = Entity::new(
                    "test/root",
                    entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                        "tag" => entity_ecf::text("ok")
                    }),
                )
                .unwrap();
                Ok(HandlerResult {
                    status: entity_handler::STATUS_OK,
                    result: root_result,
                    included,
                })
            })
        });

        // Minimal HandlerContext that carries the exec_fn — the only
        // ingredient build_dispatch_execute needs.
        let exec_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "operation" => entity_ecf::text("test"),
            "uri" => entity_ecf::text("test")
        });
        let execute = Entity::new("system/protocol/execute", exec_data).unwrap();
        let params = Entity::new("primitive/map", entity_ecf::to_ecf(&Value::Map(vec![]))).unwrap();
        let ctx = HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            pattern: String::new(),
            suffix: String::new(),
            resource_target: None,
            author: None,
            session_peer_id: None,
            request_id: "test".into(),
            operation: "test".into(),
            execute_fn: Some(exec_fn),
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        };

        let dispatch =
            build_dispatch_execute(&ctx, TEST_PID, Arc::clone(&cs)).expect("dispatch built");
        let dummy_params =
            Entity::new("test/params", entity_ecf::to_ecf(&Value::Map(vec![]))).unwrap();
        let _ = dispatch("test/path", "test", None, dummy_params, None);

        // The bundled entities MUST now be resolvable through the local
        // content store — this is what makes compute's downstream
        // navigation (e.g., walking a returned root's children) work.
        assert!(
            cs.get(&hash_a).is_some(),
            "PROPOSAL §2: included entity (hash_a) MUST be absorbed by dispatch"
        );
        assert!(
            cs.get(&hash_b).is_some(),
            "PROPOSAL §2: included entity (hash_b) MUST be absorbed by dispatch"
        );
    }
}
