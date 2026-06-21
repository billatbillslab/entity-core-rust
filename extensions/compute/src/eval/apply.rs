//! `compute/apply` — closure invocation and handler dispatch.
//!
//! Two modes share the entry (`eval_apply`):
//!   * `fn` field present → closure mode. Resolves the closure, evaluates
//!     args, builds the body scope, and tail-calls into the body.
//!   * `path` field present → handler mode. Resolves `input_type` from the
//!     handler's interface entity, builds the params entity in canonical
//!     ECF order, resolves `resource` (F1) when present, and invokes
//!     `ctx.dispatch_execute`.
//!
//! When handler mode carries a `capability` field (§3.2 voluntary restriction),
//! `resolve_apply_capability` enforces the full-resolution dual-check (F2):
//! `ctx.capability` MUST cover handler+operation+resource before we honor the
//! override. F5 makes `resource` mandatory whenever `capability` is provided —
//! without it the dual-check would skip the resource dimension and the handler
//! grant ceiling at the resource level would not be enforced.

use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_hash::Hash;

use crate::types::*;

use super::scope::{load_scope, parse_closure_entity};
use super::{
    canonical_sorted_pairs, compute_value_to_cbor, evaluate, qualify_path, EvalContext, EvalResult,
};

pub(super) fn eval_apply(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> EvalResult {
    let has_path = data.get("path").is_some();
    let has_fn = data.get("fn").is_some();

    if has_path && has_fn {
        return EvalResult::Value(
            ComputeError::InvalidExpression(
                "compute/apply has both 'path' and 'fn'".into(),
            )
            .to_value(),
        );
    }
    if !has_path && !has_fn {
        return EvalResult::Value(
            ComputeError::InvalidExpression("compute/apply requires path or fn".into())
                .to_value(),
        );
    }

    if has_fn {
        eval_apply_closure(data, scope, budget, ctx)
    } else {
        eval_apply_handler(data, scope, budget, ctx)
    }
}

fn eval_apply_closure(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> EvalResult {
    let fn_hash = match data_hash(data, "fn") {
        Some(h) => h,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression("compute/apply 'fn' is not a valid hash".into())
                    .to_value(),
            )
        }
    };

    let fn_target = match ctx.resolve_or_error(&fn_hash, "closure fn") {
        Ok(e) => e,
        Err(err) => return EvalResult::Value(err),
    };

    let fn_value = evaluate(&fn_target, scope, budget, ctx);
    if fn_value.is_error() {
        return EvalResult::Value(fn_value);
    }

    let closure = match &fn_value {
        ComputeValue::Closure(c) => c.clone(),
        ComputeValue::Entity(e) if e.entity_type == TYPE_CLOSURE => {
            match parse_closure_entity(e) {
                Some(c) => c,
                None => {
                    return EvalResult::Value(
                        ComputeError::InvalidExpression(
                            "Failed to parse closure entity".into(),
                        )
                        .to_value(),
                    )
                }
            }
        }
        _ => {
            return EvalResult::Value(
                ComputeError::TypeMismatch("Apply target is not a closure".into()).to_value(),
            )
        }
    };

    // v3.19b eager LoadScope: a scope_unreachable from any binding aborts the
    // apply with the error as a value (status 200 at the dispatch boundary).
    let mut new_scope = match load_scope(&closure.env, ctx) {
        Ok(s) => s,
        Err(err) => return EvalResult::Value(err.to_value()),
    };

    let args = data_hash_map(data, "args").unwrap_or_default();
    for param in &closure.params {
        let arg_hash = match args.iter().find(|(k, _)| k == param) {
            Some((_, h)) => *h,
            None => {
                return EvalResult::Value(
                    ComputeError::MissingArgument(format!("Missing argument: {}", param))
                        .to_value(),
                )
            }
        };

        let arg_target = match ctx.resolve_or_error(&arg_hash, &format!("closure arg {}", param)) {
            Ok(e) => e,
            Err(err) => return EvalResult::Value(err),
        };

        let arg = evaluate(&arg_target, scope, budget, ctx);
        if arg.is_error() {
            return EvalResult::Value(arg);
        }
        // §2.2 rule 11: closure-arg binding is a binding form just like
        // `compute/let` — a uint cast tag must not flow into the closure's
        // body. Strip before binding.
        new_scope.set(param.clone(), strip_cast_tag(arg));
    }

    let body_target = match ctx.resolve_or_error(&closure.body, "closure body") {
        Ok(e) => e,
        Err(err) => return EvalResult::Value(err),
    };

    // Closure-arg binding strip happened inline above (see strip_cast_tag).
    // The closure body's result IS the apply's result — cast intent can flow
    // through to a consuming operation outside the apply.
    EvalResult::TailCall {
        entity: body_target,
        scope: new_scope,
        strip_result: false,
    }
}

fn eval_apply_handler(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> EvalResult {
    let path = match data_str(data, "path") {
        Some(p) => p,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression(
                    "compute/apply handler mode missing 'path'".into(),
                )
                .to_value(),
            )
        }
    };

    let operation = match data_str(data, "operation") {
        Some(o) => o,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression(
                    "compute/apply handler mode requires 'operation'".into(),
                )
                .to_value(),
            )
        }
    };

    let args = data_hash_map(data, "args").unwrap_or_default();

    // Builtin inline-alias intercept (EXTENSION-COMPUTE §3.5 + SA-COMPUTE-V314-2).
    // For paths under system/compute/builtins/*, reconstruct the equivalent
    // inline expression entity from the raw args and evaluate it directly.
    // This mirrors Go's `builtinViaInline` and bypasses both args pre-evaluation
    // and the external dispatcher round-trip. Pure builtins ignore cap_override
    // and resource; `store` reads ctx.capability internally per §6.2.
    if crate::builtins::is_builtin_path(&path) {
        if let Some(result) =
            crate::builtins::dispatch_builtin_alias(&path, &operation, &args, scope, budget, ctx)
        {
            return EvalResult::Value(result);
        }
        // Unrecognized bare builtin name → fall through to external dispatch.
    }

    let sorted_args = canonical_sorted_pairs(&args);
    let mut resolved: Vec<(Value, Value)> = Vec::new();
    for (name, hash) in &sorted_args {
        let target = match ctx.resolve_or_error(hash, &format!("arg {}", name)) {
            Ok(e) => e,
            Err(err) => return EvalResult::Value(err),
        };
        let val = evaluate(&target, scope, budget, ctx);
        if val.is_error() {
            return EvalResult::Value(val);
        }
        resolved.push((Value::Text(name.clone()), compute_value_to_cbor(&val)));
    }

    // F1/F2/F4 (v3.10): resolve the resource expression — `compute/apply.resource`
    // mirrors EXECUTE.resource (V7 §3.3). The resolved resource is fed into both
    // the dual-check (F2) and the dispatched EXECUTE (F4) so handler-grant ceiling
    // and dispatch-chain check both run at full resolution. Absent → null
    // (handler+operation coverage only).
    let has_resource_field = data_hash(data, "resource").is_some();
    let resource = match data_hash(data, "resource") {
        Some(resource_hash) => match resolve_apply_resource(&resource_hash, scope, budget, ctx) {
            Ok(rt) => Some(rt),
            Err(err) => return EvalResult::Value(err),
        },
        None => None,
    };

    // §3.2 (v3.10 F2): when compute/apply carries a `capability` field,
    // resolve+evaluate it, dual-check ctx.capability covers the target at full
    // resolution (handler+operation+resource), and dispatch with the provided
    // capability. Without dual-check, an admin caller's broader capability could
    // escape the handler's declared scope.
    //
    // F5: capability requires resource. Without it the dual-check below would
    // see null resource and the handler-grant ceiling at the resource level
    // would not be enforced — which is exactly the bug F1-F5 closes.
    let cap_override = match data_hash(data, "capability") {
        Some(cap_hash) => {
            if !has_resource_field {
                return EvalResult::Value(
                    ComputeError::InvalidExpression(
                        "compute/apply with capability field MUST also have resource field"
                            .into(),
                    )
                    .to_value(),
                );
            }
            match resolve_apply_capability(
                &cap_hash,
                &path,
                &operation,
                resource.as_ref(),
                scope,
                budget,
                ctx,
            ) {
                Ok(entity) => Some(entity),
                Err(err) => return EvalResult::Value(err),
            }
        }
        None => None,
    };

    // §4.1 / §2.1 (proposal §3.2): assemble params using the target operation's
    // declared input_type (resolved via tree walk to the handler manifest +
    // interface entity). Cross-implementation interop requires the params
    // entity carry the handler's declared input type, not a generic primitive/map.
    // When the type definition is unavailable, fall back to primitive/map (the
    // spec's fall-back path when type extension isn't present).
    let params_type =
        resolve_operation_input_type(ctx, &path, &operation).unwrap_or_else(|| {
            // Builtins are not user-registered tree handlers — their input_type
            // comes from the spec (§3.5 §912 table). Fall back to the canonical
            // type before resorting to primitive/map so cross-impl hashing of
            // the params entity stays stable.
            if let Some(t) = crate::builtins::builtin_input_type(&path, &operation) {
                return t.to_string();
            }
            tracing::debug!(
                handler = %path,
                operation = %operation,
                "compute/apply: input_type lookup failed, falling back to primitive/map"
            );
            "primitive/map".to_string()
        });

    let params_data = Value::Map(resolved);
    let params_bytes = entity_ecf::to_ecf(&params_data);
    let params_entity = match Entity::new(&params_type, params_bytes) {
        Ok(e) => e,
        Err(_) => {
            return EvalResult::Value(
                ComputeError::InvalidExpression("Failed to build params entity".into()).to_value(),
            )
        }
    };

    let dispatch = match &ctx.dispatch_execute {
        Some(f) => f,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression(
                    "Handler dispatch not available in this evaluation context".into(),
                )
                .to_value(),
            )
        }
    };

    EvalResult::Value(dispatch(
        &path,
        &operation,
        resource,
        params_entity,
        cap_override,
    ))
}

/// Walk the tree backward from `path` to find the longest-prefix `system/handler`
/// entity (V7 §6.6). Returns the matched handler entity, or None if no handler
/// exists along the path. Pure tree-only resolution — no registry consulted.
fn resolve_handler_entity_in_tree(
    ctx: &EvalContext<'_>,
    path: &str,
) -> Option<Entity> {
    let qualified = qualify_path(path, ctx.local_peer_id);
    let segments: Vec<&str> = qualified.split('/').filter(|s| !s.is_empty()).collect();
    for i in (1..=segments.len()).rev() {
        let prefix = format!("/{}", segments[..i].join("/"));
        let hash = ctx.location_index.get(&prefix)?;
        if let Some(entity) = ctx.content_store.get(&hash) {
            if entity.entity_type == "system/handler" {
                return Some(entity);
            }
        }
    }
    None
}

/// Resolve the declared `input_type` for an operation on the handler at `path`.
///
/// Walks: dispatch path → handler entity → interface path → interface entity →
/// operations[op].input_type. Returns None when any step is missing — caller
/// falls back to `primitive/map` per spec (no type-extension scenario).
fn resolve_operation_input_type(
    ctx: &EvalContext<'_>,
    path: &str,
    operation: &str,
) -> Option<String> {
    let handler_entity = resolve_handler_entity_in_tree(ctx, path)?;
    let handler_data = decode_data(&handler_entity)?;
    let interface_path = data_str(&handler_data, "interface")?;
    let qualified_interface = qualify_path(&interface_path, ctx.local_peer_id);
    let iface_hash = ctx.location_index.get(&qualified_interface)?;
    let iface_entity = ctx.content_store.get(&iface_hash)?;
    let iface_data = decode_data(&iface_entity)?;
    let operations = iface_data.get("operations")?;
    let op_spec = operations.get(operation)?;
    op_spec
        .get("input_type")
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
}

/// Resolve a `compute/apply.resource` reference into a `ResourceTarget` (F1).
///
/// Same resolve-then-evaluate pattern as `capability`. The result must be a
/// `system/protocol/resource-target`-shaped value — either as a primitive map
/// (from `compute/literal`) or as a `system/protocol/resource-target` entity.
fn resolve_apply_resource(
    resource_hash: &Hash,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> Result<entity_capability::ResourceTarget, ComputeValue> {
    let resource_ref = ctx.resolve_or_error(resource_hash, "apply resource")?;
    let value = evaluate(&resource_ref, scope, budget, ctx);
    match value {
        ComputeValue::Primitive(v) => crate::walker::decode_resource_target(&v).ok_or_else(|| {
            ComputeError::TypeMismatch(
                "compute/apply 'resource' must evaluate to a {targets, exclude} map".into(),
            )
            .to_value()
        }),
        ComputeValue::Entity(e) => {
            if e.entity_type != "system/protocol/resource-target" {
                return Err(ComputeError::TypeMismatch(format!(
                    "compute/apply 'resource' must evaluate to a system/protocol/resource-target (got {})",
                    e.entity_type,
                ))
                .to_value());
            }
            let data = match decode_data(&e) {
                Some(d) => d,
                None => {
                    return Err(ComputeError::InvalidExpression(
                        "Failed to decode resource-target entity data".into(),
                    )
                    .to_value())
                }
            };
            crate::walker::decode_resource_target(&data).ok_or_else(|| {
                ComputeError::InvalidExpression(
                    "Invalid resource-target entity shape (expected {targets, exclude})".into(),
                )
                .to_value()
            })
        }
        ComputeValue::Error(err) => Err(err.to_value()),
        ComputeValue::Closure(_) => Err(ComputeError::TypeMismatch(
            "compute/apply 'resource' must evaluate to a resource-target, not a closure".into(),
        )
        .to_value()),
        ComputeValue::Uint(_) => Err(ComputeError::TypeMismatch(
            "compute/apply 'resource' must evaluate to a resource-target, not an integer".into(),
        )
        .to_value()),
    }
}

/// Resolve and dual-check a compute/apply `capability` field (§3.2 / F2).
///
/// Returns the provided capability entity to use as the dispatch override, or a
/// ComputeValue error if either the resolution fails or the dual-check denies.
///
/// `resource` is `Some` only when `compute/apply.resource` was provided — F5
/// guarantees this at the call site whenever a `capability` override is set,
/// so the dual-check below runs at full resolution.
fn resolve_apply_capability(
    cap_hash: &Hash,
    target_path: &str,
    target_op: &str,
    resource: Option<&entity_capability::ResourceTarget>,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> Result<Entity, ComputeValue> {
    // Resolve the hash reference and evaluate it (per spec — resolve-then-evaluate
    // pattern, identical to other system/hash field references).
    let cap_ref = ctx.resolve_or_error(cap_hash, "apply capability")?;
    let cap_value = evaluate(&cap_ref, scope, budget, ctx);
    let cap_entity = match cap_value {
        ComputeValue::Entity(e) => e,
        ComputeValue::Error(err) => return Err(err.to_value()),
        _ => {
            return Err(ComputeError::TypeMismatch(
                "compute/apply 'capability' must resolve to an entity".into(),
            )
            .to_value());
        }
    };

    // F2 dual-check: ctx.capability (handler grant) MUST cover handler+op+resource
    // before we honor the override. Resource is mandatory here per F5; without
    // it the resource scope check would silently pass and the handler grant
    // ceiling would not bind at the resource level — exactly the bug v3.10 closes.
    let ctx_cap = match ctx.capability {
        Some(c) => c,
        None => {
            return Err(ComputeError::PermissionDenied(format!(
                "compute/apply 'capability' field requires ctx.capability for dual-check ({}:{})",
                target_path, target_op,
            ))
            .to_value());
        }
    };

    let qualified_target = qualify_path(target_path, ctx.local_peer_id);
    if !entity_capability::check_permission(
        target_op,
        &qualified_target,
        ctx.local_peer_id,
        resource,
        ctx_cap,
        ctx.local_peer_id,
    ) {
        return Err(ComputeError::PermissionDenied(format!(
            "Handler grant does not cover target: {}.{}",
            target_path, target_op,
        ))
        .to_value());
    }

    Ok(cap_entity)
}
