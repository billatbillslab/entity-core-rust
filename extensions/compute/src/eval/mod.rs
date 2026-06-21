//! Compute expression evaluator (§4.1).
//!
//! Decomposed into category submodules:
//!
//!   * [`lookup`]     — `compute/literal`, `compute/lookup/{scope,tree,hash}`
//!   * [`apply`]      — `compute/apply` closure + handler dispatch
//!   * [`control`]    — `compute/{if,let,lambda}`
//!   * [`ops`]        — `compute/{arithmetic,compare,logic}` + pure math
//!   * [`construct`]  — `compute/{field,construct}`
//!   * [`scope`]      — closure scope serialize / load / parse
//!
//! This module owns the entry point ([`evaluate`]), the trampoline that
//! flattens tail calls to O(1) depth, the [`EvalContext`] threaded through
//! every evaluator, and a handful of cross-cutting helpers
//! ([`eval_hash_ref`], [`compute_value_to_cbor`], [`canonical_sorted_pairs`],
//! [`qualify_path`], [`resolve_relative_path`]).

use std::collections::{HashMap, HashSet};

use ciborium::Value;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::resolve::{resolve, resolve_or_error};
use crate::types::*;

mod apply;
mod construct;
mod control;
mod lookup;
mod ops;
mod scope;

// Bring submodule expression evaluators into local scope so `evaluate_inner`
// dispatches without per-call qualification, and so the test module under
// `mod tests` reaches them via `use super::*`.
use apply::eval_apply;
use construct::{eval_construct, eval_field, eval_index, eval_length};
use control::{eval_if, eval_lambda, eval_let};
use lookup::{eval_literal, eval_lookup_hash, eval_lookup_scope, eval_lookup_tree};
use ops::{eval_arithmetic, eval_compare, eval_logic};

// External crates depend on these by name as `crate::eval::*` — re-export.
pub use ops::{apply_arithmetic, apply_compare};
// v3.19b: scope load is shared by builtins (filter/map/fold closures).
pub(crate) use scope::load_scope as load_scope_kind_tagged;
// v3.19c α: the kind-tagged construct encoder is gone — construct
// produces bare V7 §1.4 form directly (`encode_construct_field_bare` in
// `eval/construct.rs`); the prior `load_scope_kind_tagged_encode` re-export is
// withdrawn.

// ---------------------------------------------------------------------------
// EvalContext — evaluation context threaded through calls
// ---------------------------------------------------------------------------

/// Handler dispatch callback type for compute/apply handler mode.
///
/// Arguments: `(handler_path, operation, resource, params, capability_override)`.
///
/// `resource` is the resolved value of `compute/apply.resource` (F1, v3.10) —
/// passed to the constructed EXECUTE so the dispatch chain runs full-resolution
/// scope checks. `None` means no resource field on the EXECUTE (handler+operation
/// coverage only; same as omitting `resource` from `compute/apply`).
///
/// `capability_override` is `None` to use `ctx.capability`, or `Some(entity)`
/// to use the resolved value of `compute/apply.capability` (§3.2 voluntary
/// restriction). Dual-check enforcement against `ctx.capability` AT FULL
/// RESOLUTION happens at the call site before invoking this — see F2.
pub type DispatchExecuteFn<'a> = Box<
    dyn Fn(
            &str,
            &str,
            Option<entity_capability::ResourceTarget>,
            Entity,
            Option<Entity>,
        ) -> ComputeValue
        + 'a,
>;

pub struct EvalContext<'a> {
    pub content_store: &'a dyn ContentStore,
    pub location_index: &'a dyn LocationIndex,
    pub included: &'a HashMap<Hash, Entity>,
    pub local_peer_id: &'a str,
    /// The eval authority — authorizes every impure operation in the expression.
    /// Sources per §6.1 of PROPOSAL-ENTITY-NATIVE-HANDLER-DISPATCH:
    ///   - Explicit eval: caller's capability
    ///   - Reactive re-eval: installation grant
    ///   - Entity-native dispatch: handler grant
    pub capability: Option<&'a entity_capability::CapabilityToken>,
    /// The external caller's capability — separate from `capability` for entity-native
    /// dispatch where `capability` is the handler grant. Used for voluntary restriction
    /// (compute/apply `capability` field) and history attribution (emit pathway).
    /// Absent for explicit eval (caller cap == ctx.capability) and reactive (autonomous).
    pub caller_capability: Option<&'a entity_capability::CapabilityToken>,
    pub encountered: HashMap<Hash, Entity>,
    /// v3.19c α + N3 ruling (arch 6e73d3d): per-eval in-flight tracking for
    /// `compute/construct` results. Keyed by the materialized entity's
    /// `content_hash`; value is the original `name → ComputeValue` map of
    /// field values *before* materialization to bare V7 §1.4 form. This is
    /// what lets `field(field(construct(…),"inner"),"name")` compose during
    /// the constructing eval: when extract_field hits a `ComputeValue::Entity`
    /// whose hash is in this map, it returns the in-flight original value
    /// (typed). When the hash is NOT in this map (e.g. a re-read materialized
    /// entity from a prior eval), it returns the bare data per N3 — no
    /// shape-sniffing, caller follows refs explicitly via `compute/lookup/hash`.
    pub constructed_in_flight: HashMap<Hash, HashMap<String, ComputeValue>>,
    pub dependency_paths: Option<Vec<String>>,
    /// Sealed set of authorized non-compute data hashes (D5, v3.7).
    /// Populated from subgraph metadata during reactive re-evaluation.
    pub authorized_data_hashes: HashSet<Hash>,
    /// Subgraph root path for resolving relative paths (R1-R2, v3.8).
    pub subgraph_root: Option<String>,
    /// Handler dispatch callback for compute/apply handler mode.
    /// Called with (handler_path, operation, params_entity, dispatch_capability) -> ComputeValue.
    /// dispatch_capability is None to use ctx.capability, or Some(entity) to override
    /// (used by §3.2 voluntary restriction via the `capability` field).
    pub dispatch_execute: Option<DispatchExecuteFn<'a>>,
}

impl<'a> EvalContext<'a> {
    pub fn new(
        content_store: &'a dyn ContentStore,
        location_index: &'a dyn LocationIndex,
        included: &'a HashMap<Hash, Entity>,
        local_peer_id: &'a str,
    ) -> Self {
        Self {
            content_store,
            location_index,
            included,
            local_peer_id,
            capability: None,
            caller_capability: None,
            encountered: HashMap::new(),
            constructed_in_flight: HashMap::new(),
            dependency_paths: None,
            authorized_data_hashes: HashSet::new(),
            subgraph_root: None,
            dispatch_execute: None,
        }
    }

    pub fn with_capability(mut self, cap: Option<&'a entity_capability::CapabilityToken>) -> Self {
        self.capability = cap;
        self
    }

    pub fn with_caller_capability(
        mut self,
        cap: Option<&'a entity_capability::CapabilityToken>,
    ) -> Self {
        self.caller_capability = cap;
        self
    }

    pub fn with_authorized_hashes(mut self, hashes: HashSet<Hash>) -> Self {
        self.authorized_data_hashes = hashes;
        self
    }

    pub fn with_subgraph_root(mut self, root: Option<String>) -> Self {
        self.subgraph_root = root;
        self
    }

    pub fn with_dispatch_execute(
        mut self,
        f: Option<DispatchExecuteFn<'a>>,
    ) -> Self {
        self.dispatch_execute = f;
        self
    }

    pub fn resolve(&self, hash: &Hash) -> Option<Entity> {
        resolve(
            hash,
            self.included,
            &self.encountered,
            self.content_store,
            &self.authorized_data_hashes,
        )
    }

    pub fn resolve_or_error(&self, hash: &Hash, label: &str) -> Result<Entity, ComputeValue> {
        resolve_or_error(
            hash,
            self.included,
            &self.encountered,
            self.content_store,
            &self.authorized_data_hashes,
            label,
        )
    }
}

// ---------------------------------------------------------------------------
// Evaluate (§4.1) — trampoline for tail call optimization (T1–T3, v3.8)
// ---------------------------------------------------------------------------

/// Internal result type: either a final value or a tail-call continuation.
///
/// Visible to submodules (they construct it from their own evaluators) but
/// not exported — external crates only see the final `ComputeValue`.
///
/// `strip_result` (v3.17 SA-AMD3-1 / rule 11): when an evaluator hands the
/// trampoline a `TailCall` whose surrounding form is a strip point for cast
/// intent — currently only `compute/if` branches — it sets `strip_result =
/// true`. The trampoline OR-accumulates these across the iteration chain and
/// calls `strip_cast_tag` on the eventual `Value`. This preserves TCO for
/// recursive function chains (we never call `evaluate()` recursively) while
/// honoring the spec's "indirection drops the unsigned intent" rule.
pub(crate) enum EvalResult {
    Value(ComputeValue),
    TailCall {
        entity: Entity,
        scope: Scope,
        strip_result: bool,
    },
}

/// Main evaluation entry point. Trampoline loop handles tail calls in O(1) depth.
///
/// Non-compute entities are returned as-is (ComputeValue::Entity).
/// Compute expressions are evaluated per §4.1.
/// Depth is checked and decremented once on entry; tail calls reuse the slot.
/// Budget is decremented every iteration (tail or not).
///
/// On native targets, `stacker::maybe_grow` ensures non-tail recursion doesn't
/// overflow the thread stack — each recursive `evaluate()` call from sub-expression
/// evaluation (arithmetic operands, apply args, condition checks) checks remaining
/// stack and grows if needed.
pub fn evaluate(
    entity: &Entity,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    #[cfg(not(target_arch = "wasm32"))]
    {
        stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || {
            evaluate_trampoline(entity, scope, budget, ctx)
        })
    }
    #[cfg(target_arch = "wasm32")]
    {
        evaluate_trampoline(entity, scope, budget, ctx)
    }
}

fn evaluate_trampoline(
    entity: &Entity,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    if !is_compute_expression(entity) {
        return ComputeValue::Entity(entity.clone());
    }

    if budget.depth == 0 {
        return ComputeError::DepthExceeded.to_value();
    }
    budget.depth -= 1;

    let mut current_entity = entity.clone();
    let mut current_scope = scope.clone();
    // v3.17 rule 11: monotonically OR-accumulated. Any `compute/if` branch
    // (or future strip-point form) along the tail-call chain sets it; the
    // final Value is stripped of its cast tag before returning. Idempotent
    // for non-Uint values, so over-stripping is harmless.
    let mut strip_pending = false;

    loop {
        budget.operations = budget.operations.saturating_sub(1);
        if budget.operations == 0 {
            budget.depth += 1;
            return ComputeError::BudgetExhausted.to_value();
        }

        match evaluate_inner(&current_entity, &current_scope, budget, ctx) {
            EvalResult::TailCall { entity: next, scope: next_scope, strip_result } => {
                if strip_result {
                    strip_pending = true;
                }
                if !is_compute_expression(&next) {
                    budget.depth += 1;
                    let result = ComputeValue::Entity(next);
                    return if strip_pending { strip_cast_tag(result) } else { result };
                }
                current_entity = next;
                current_scope = next_scope;
            }
            EvalResult::Value(value) => {
                budget.depth += 1;
                return if strip_pending { strip_cast_tag(value) } else { value };
            }
        }
    }
}

fn evaluate_inner(
    entity: &Entity,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> EvalResult {
    let data = match decode_data(entity) {
        Some(d) => d,
        None => {
            return EvalResult::Value(
                ComputeError::InvalidExpression("cannot decode entity data".into()).to_value(),
            )
        }
    };

    match entity.entity_type.as_str() {
        TYPE_LITERAL => EvalResult::Value(eval_literal(&data)),
        TYPE_LOOKUP_SCOPE => EvalResult::Value(eval_lookup_scope(&data, scope)),
        TYPE_LOOKUP_TREE => eval_lookup_tree(&data, scope, budget, ctx),
        TYPE_LOOKUP_HASH => eval_lookup_hash(&data, scope, budget, ctx),
        TYPE_APPLY => eval_apply(&data, scope, budget, ctx),
        TYPE_IF => eval_if(&data, scope, budget, ctx),
        TYPE_LET => eval_let(&data, scope, budget, ctx),
        TYPE_LAMBDA => EvalResult::Value(eval_lambda(&data, scope, budget, ctx)),
        TYPE_ARITHMETIC => EvalResult::Value(eval_arithmetic(&data, scope, budget, ctx)),
        TYPE_COMPARE => EvalResult::Value(eval_compare(&data, scope, budget, ctx)),
        TYPE_LOGIC => EvalResult::Value(eval_logic(&data, scope, budget, ctx)),
        TYPE_FIELD => EvalResult::Value(eval_field(&data, scope, budget, ctx)),
        TYPE_CONSTRUCT => EvalResult::Value(eval_construct(&data, scope, budget, ctx)),
        TYPE_INDEX => EvalResult::Value(eval_index(&data, scope, budget, ctx)),
        TYPE_LENGTH => EvalResult::Value(eval_length(&data, scope, budget, ctx)),
        TYPE_NUMERIC_CAST => EvalResult::Value(ops::eval_numeric_cast(&data, scope, budget, ctx)),
        other => EvalResult::Value(
            ComputeError::UnknownType(format!("Unknown compute type: {}", other)).to_value(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Cross-cutting helpers (consumed by multiple submodules)
// ---------------------------------------------------------------------------

/// Evaluate a hash-referenced sub-expression from a data field.
///
/// Used by `ops` (arithmetic/compare/logic operands) and `construct` (field
/// targets) to resolve a `system/hash` field into a value before applying
/// the surrounding operator.
pub(crate) fn eval_hash_ref(
    data: &Value,
    key: &str,
    label: &str,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let hash = match data_hash(data, key) {
        Some(h) => h,
        None => {
            return ComputeError::InvalidExpression(format!(
                "Missing or invalid hash field '{}'",
                key
            ))
            .to_value()
        }
    };

    let target = match ctx.resolve_or_error(&hash, label) {
        Ok(e) => e,
        Err(err) => return err,
    };

    evaluate(&target, scope, budget, ctx)
}

/// Convert a ComputeValue to a CBOR value for embedding in entity data.
pub(crate) fn compute_value_to_cbor(value: &ComputeValue) -> Value {
    match value {
        ComputeValue::Primitive(v) => v.clone(),
        ComputeValue::Entity(e) => Value::Bytes(e.content_hash.to_bytes().to_vec()),
        ComputeValue::Closure(c) => Value::Bytes(c.to_entity().content_hash.to_bytes().to_vec()),
        ComputeValue::Error(err) => {
            Value::Bytes(err.to_entity().content_hash.to_bytes().to_vec())
        }
        ComputeValue::Uint(u) => Value::Integer(ciborium::value::Integer::from(*u)),
    }
}

/// Sort (name, hash) pairs in ECF canonical map key order (§8.2).
///
/// ECF canonical: sort by encoded byte length of key, then lexicographically.
/// For string keys this is: shorter strings first, then alphabetical within same length.
pub(crate) fn canonical_sorted_pairs(pairs: &[(String, Hash)]) -> Vec<(String, Hash)> {
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|(a, _), (b, _)| {
        let a_len = ecf_key_encoded_len(a);
        let b_len = ecf_key_encoded_len(b);
        a_len.cmp(&b_len).then_with(|| a.as_bytes().cmp(b.as_bytes()))
    });
    sorted
}

/// Byte length of a CBOR text string encoding for sorting purposes.
fn ecf_key_encoded_len(s: &str) -> usize {
    let text_bytes = entity_ecf::to_ecf(&Value::Text(s.to_string()));
    text_bytes.len()
}

/// Resolve a relative path against a subgraph root (R1-R2, v3.8).
/// If no root is set, returns the path unchanged.
pub fn resolve_relative_path(root: Option<&str>, path: &str) -> String {
    match root {
        Some(r) => format!(
            "{}/{}",
            r.trim_end_matches('/'),
            path.trim_start_matches('/')
        ),
        None => path.to_string(),
    }
}

/// Qualify a bare path with the local peer ID if not already qualified.
pub fn qualify_path(path: &str, local_peer_id: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}/{}", local_peer_id, path)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
