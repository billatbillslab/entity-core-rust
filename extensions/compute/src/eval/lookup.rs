//! Lookup expressions: `compute/literal`, `compute/lookup/{scope,tree,hash}`.
//!
//! All four are leaves of the expression DAG — they don't call `evaluate`
//! directly. `compute/lookup/tree` enforces the §7.2 capability check
//! (PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH) before touching the index.

use ciborium::Value;
use entity_ecf::ValueExt;

use crate::types::*;

use super::{qualify_path, resolve_relative_path, EvalContext, EvalResult};

pub(super) fn eval_literal(data: &Value) -> ComputeValue {
    match data.get("value") {
        Some(v) => ComputeValue::Primitive(v.clone()),
        None => ComputeError::InvalidExpression("compute/literal missing 'value' field".into())
            .to_value(),
    }
}

pub(super) fn eval_lookup_scope(data: &Value, scope: &Scope) -> ComputeValue {
    let name = match data_str(data, "name") {
        Some(n) => n,
        None => {
            return ComputeError::InvalidExpression(
                "compute/lookup/scope missing 'name' field".into(),
            )
            .to_value()
        }
    };

    match scope.get(&name) {
        Some(v) => v.clone(),
        None => ComputeError::NotFound(format!("No scope binding: {}", name)).to_value(),
    }
}

pub(super) fn eval_lookup_tree(
    data: &Value,
    scope: &Scope,
    _budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> EvalResult {
    let path = match data_str(data, "path") {
        Some(p) => p,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression(
                    "compute/lookup/tree missing 'path' field".into(),
                )
                .to_value(),
            )
        }
    };

    let resolved_path = if data_bool(data, "relative") == Some(true) {
        resolve_relative_path(ctx.subgraph_root.as_deref(), &path)
    } else {
        path.clone()
    };

    // §7.2 (PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH §7.2 — CRITICAL): ctx.capability
    // MUST cover the tree read before we touch the index. For reactive mode this is
    // a redundant check (install audit covers it), but uniform enforcement is required
    // for explicit eval and entity-native dispatch which have no upfront audit.
    match ctx.capability {
        Some(cap) => {
            let resource = entity_capability::ResourceTarget {
                targets: vec![resolved_path.clone()],
                exclude: vec![],
            };
            let tree_pattern = format!("/{}/system/tree", ctx.local_peer_id);
            if !entity_capability::check_permission(
                "get",
                &tree_pattern,
                ctx.local_peer_id,
                Some(&resource),
                cap,
                ctx.local_peer_id,
            ) {
                return EvalResult::Value(
                    ComputeError::PermissionDenied(format!(
                        "Capability does not cover tree read: {}",
                        resolved_path
                    ))
                    .to_value(),
                );
            }
        }
        None => {
            return EvalResult::Value(
                ComputeError::PermissionDenied(format!(
                    "No capability available for tree read: {}",
                    resolved_path
                ))
                .to_value(),
            );
        }
    }

    if let Some(ref mut deps) = ctx.dependency_paths {
        deps.push(resolved_path.clone());
    }

    let qualified = qualify_path(&resolved_path, ctx.local_peer_id);

    let hash = match ctx.location_index.get(&qualified) {
        Some(h) => h,
        None => {
            return EvalResult::Value(
                ComputeError::NotFound(format!("No entity at path: {}", resolved_path)).to_value(),
            )
        }
    };

    let tree_entity = match ctx.content_store.get(&hash) {
        Some(e) => e,
        None => {
            return EvalResult::Value(
                ComputeError::NotFound(format!("No entity at path: {}", resolved_path)).to_value(),
            )
        }
    };

    ctx.encountered
        .insert(tree_entity.content_hash, tree_entity.clone());

    EvalResult::TailCall {
        entity: tree_entity,
        scope: scope.clone(),
        strip_result: false,
    }
}

/// Hash lookup — pure, authorized via sealed set or content_store_access (v3.7 D6).
pub(super) fn eval_lookup_hash(
    data: &Value,
    scope: &Scope,
    _budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> EvalResult {
    let hash = match data_hash(data, "hash") {
        Some(h) => h,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression(
                    "compute/lookup/hash missing 'hash' field".into(),
                )
                .to_value(),
            )
        }
    };

    let target = match ctx.resolve_or_error(&hash, "hash lookup") {
        Ok(e) => e,
        Err(err) => return EvalResult::Value(err),
    };

    EvalResult::TailCall {
        entity: target,
        scope: scope.clone(),
        strip_result: false,
    }
}
