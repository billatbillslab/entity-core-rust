//! Control-flow expressions: `compute/if`, `compute/let`, `compute/lambda`.
//!
//! `eval_if` and `eval_let` are tail-position constructs that return
//! `EvalResult::TailCall` so the trampoline can iterate them in O(1) depth.
//! `eval_lambda` captures the surrounding scope into a closure value.

use ciborium::Value;
use entity_ecf::ValueExt;
use entity_hash::Hash;

use crate::types::*;

use super::scope::capture_scope;
use super::{evaluate, EvalContext, EvalResult};

pub(super) fn eval_if(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> EvalResult {
    let cond_hash = match data_hash(data, "condition") {
        Some(h) => h,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression("compute/if missing 'condition'".into())
                    .to_value(),
            )
        }
    };

    let cond_target = match ctx.resolve_or_error(&cond_hash, "if condition") {
        Ok(e) => e,
        Err(err) => return EvalResult::Value(err),
    };

    let condition = evaluate(&cond_target, scope, budget, ctx);
    if condition.is_error() {
        return EvalResult::Value(condition);
    }

    if condition.is_truthy() {
        let then_hash = match data_hash(data, "then") {
            Some(h) => h,
            None => {
                return EvalResult::Value(
                    ComputeError::InvalidExpression("compute/if missing 'then'".into())
                        .to_value(),
                )
            }
        };
        let then_target = match ctx.resolve_or_error(&then_hash, "if then") {
            Ok(e) => e,
            Err(err) => return EvalResult::Value(err),
        };
        // §2.2 rule 11 (v3.17): cast intent does not flow through a
        // compute/if branch. The trampoline strips the eventual Value.
        EvalResult::TailCall {
            entity: then_target,
            scope: scope.clone(),
            strip_result: true,
        }
    } else if let Some(else_hash) = data_hash(data, "else") {
        let else_target = match ctx.resolve_or_error(&else_hash, "if else") {
            Ok(e) => e,
            Err(err) => return EvalResult::Value(err),
        };
        EvalResult::TailCall {
            entity: else_target,
            scope: scope.clone(),
            strip_result: true,
        }
    } else {
        EvalResult::Value(ComputeValue::Primitive(Value::Null))
    }
}

pub(super) fn eval_let(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> EvalResult {
    let bindings = match data.get("bindings").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression("compute/let missing 'bindings' array".into())
                    .to_value(),
            )
        }
    };

    let body_hash = match data_hash(data, "body") {
        Some(h) => h,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression("compute/let missing 'body'".into()).to_value(),
            )
        }
    };

    let mut new_scope = scope.clone();
    for binding in bindings {
        let name = match binding.get("name").and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => {
                return EvalResult::Value(
                    ComputeError::InvalidExpression("let binding missing 'name'".into())
                        .to_value(),
                )
            }
        };

        let value_hash = match binding.get("value").and_then(|v| v.as_bytes()) {
            Some(b) => match Hash::from_bytes(b) {
                Ok(h) => h,
                Err(_) => {
                    return EvalResult::Value(
                        ComputeError::InvalidExpression(
                            "let binding 'value' is not a valid hash".into(),
                        )
                        .to_value(),
                    )
                }
            },
            None => {
                return EvalResult::Value(
                    ComputeError::InvalidExpression("let binding missing 'value'".into())
                        .to_value(),
                )
            }
        };

        let value_target =
            match ctx.resolve_or_error(&value_hash, &format!("let binding {}", name)) {
                Ok(e) => e,
                Err(err) => return EvalResult::Value(err),
            };

        let value = evaluate(&value_target, &new_scope, budget, ctx);
        if value.is_error() {
            return EvalResult::Value(value);
        }
        // §2.2 rule 11: cast intent does NOT flow through compute/let
        // bindings. A `numeric-cast → uint` consumed by the binding loses
        // its tag — the bound value goes into scope as a plain integer.
        new_scope.set(name, strip_cast_tag(value));
    }

    let body_target = match ctx.resolve_or_error(&body_hash, "let body") {
        Ok(e) => e,
        Err(err) => return EvalResult::Value(err),
    };

    // Per spec §287: the strip points are let *binding* (handled above via
    // strip_cast_tag), if branch, lookup/scope, construct field, closure-arg
    // binding. The let *body*'s result IS the let's result; the cast intent
    // does flow through into whatever consumes the let. So strip_result=false.
    EvalResult::TailCall {
        entity: body_target,
        scope: new_scope,
        strip_result: false,
    }
}

pub(super) fn eval_lambda(
    data: &Value,
    scope: &Scope,
    _budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let params = match data_str_array(data, "params") {
        Some(p) => p,
        None => {
            return ComputeError::InvalidExpression("compute/lambda missing 'params'".into())
                .to_value()
        }
    };

    let body = match data_hash(data, "body") {
        Some(h) => h,
        None => {
            return ComputeError::InvalidExpression("compute/lambda missing 'body'".into())
                .to_value()
        }
    };

    let env = capture_scope(scope, ctx);

    ComputeValue::Closure(ClosureValue {
        params,
        body,
        env,
    })
}
