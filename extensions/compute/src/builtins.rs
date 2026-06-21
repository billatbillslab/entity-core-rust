use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_hash::Hash;

use crate::eval::{self, apply_arithmetic, apply_compare, qualify_path, EvalContext};
use crate::types::*;

pub const BUILTIN_PREFIX: &str = "system/compute/builtins/";

pub const BUILTIN_ARITHMETIC: &str = "system/compute/builtins/arithmetic";
pub const BUILTIN_COMPARE: &str = "system/compute/builtins/compare";
pub const BUILTIN_LOGIC: &str = "system/compute/builtins/logic";
pub const BUILTIN_FIELD: &str = "system/compute/builtins/field";
pub const BUILTIN_CONSTRUCT: &str = "system/compute/builtins/construct";
pub const BUILTIN_MAP: &str = "system/compute/builtins/map";
pub const BUILTIN_FILTER: &str = "system/compute/builtins/filter";
pub const BUILTIN_FOLD: &str = "system/compute/builtins/fold";
pub const BUILTIN_STORE: &str = "system/compute/builtins/store";

pub const ALL_BUILTINS: &[&str] = &[
    BUILTIN_ARITHMETIC,
    BUILTIN_COMPARE,
    BUILTIN_LOGIC,
    BUILTIN_FIELD,
    BUILTIN_CONSTRUCT,
    BUILTIN_MAP,
    BUILTIN_FILTER,
    BUILTIN_FOLD,
    BUILTIN_STORE,
];

/// Check if a path is a builtin handler path.
pub fn is_builtin_path(path: &str) -> bool {
    path.starts_with(BUILTIN_PREFIX)
        || path.contains("/system/compute/builtins/")
}

/// Spec-pinned input_type for a builtin handler's operation (§3.5 §912).
///
/// Compute/apply's params-entity construction uses this when the tree has no
/// registered handler entity at the builtin path. Returns the canonical type
/// name so the constructed params entity hashes identically across impls.
/// Returns None for unknown builtin names or non-eval operations.
pub fn builtin_input_type(path: &str, operation: &str) -> Option<&'static str> {
    if operation != "eval" {
        return None;
    }
    let bare = extract_bare_builtin(path)?;
    Some(match bare {
        "arithmetic" => TYPE_ARITHMETIC,
        "compare" => TYPE_COMPARE,
        "logic" => TYPE_LOGIC,
        "field" => TYPE_FIELD,
        "construct" => TYPE_CONSTRUCT,
        "map" => TYPE_MAP_ARGS,
        "filter" => TYPE_FILTER_ARGS,
        "fold" => TYPE_FOLD_ARGS,
        "store" => TYPE_STORE_ARGS,
        _ => return None,
    })
}

/// Inline-alias dispatch for `compute/apply { path: system/compute/builtins/X, args: {...} }`.
///
/// Mirrors Go's `builtinViaInline` (EXTENSION-COMPUTE §3.5 alias intercept):
/// rebuild the equivalent inline expression entity from the raw args map and
/// run the inline evaluator. The args map's values are kept as hashes for
/// `system/hash`-typed fields (left/right/entity/collection/fn/
/// initial/value) and resolved+evaluated for primitive-typed fields
/// (op/name/entity_type/path).
///
/// This is the path the cross-impl validator exercises via `v314_builtin_*`
/// vectors. Returns `None` for unknown builtin paths (caller falls through to
/// external dispatch).
pub fn dispatch_builtin_alias(
    path: &str,
    operation: &str,
    args: &[(String, entity_hash::Hash)],
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> Option<ComputeValue> {
    if operation != "eval" {
        return Some(
            ComputeError::InvalidExpression(format!(
                "builtin {} requires operation 'eval', got '{}'",
                path, operation
            ))
            .to_value(),
        );
    }
    let bare = extract_bare_builtin(path)?;
    let result = match bare {
        "arithmetic" => alias_arithmetic(args, scope, budget, ctx),
        "compare" => alias_compare(args, scope, budget, ctx),
        "logic" => alias_logic(args, scope, budget, ctx),
        "field" => alias_field(args, scope, budget, ctx),
        "construct" => alias_construct(args, scope, budget, ctx),
        // `store-args` is the only builtin input type with a mixed field
        // schema (`path: system/tree/path` + `value: system/hash`), so it
        // needs SA-2 per-field encoding: `path` resolves to a string,
        // `value` keeps its hash. The dispatch_store body then evaluates
        // `value` per SA-9.
        "store" => alias_store(args, scope, budget, ctx),
        // Collection builtins' input types are all `system/hash`, so the
        // generic "every arg is hash bytes" build is correct here.
        "map" | "filter" | "fold" => {
            let input_type = builtin_input_type(path, operation)?;
            let params = match build_typed_args_entity(input_type, args) {
                Ok(e) => e,
                Err(err) => return Some(err.to_value()),
            };
            return dispatch_builtin(path, operation, &params, scope, budget, ctx);
        }
        _ => return None,
    };
    Some(result)
}

/// Build an entity of `entity_type` with fields = {name → Value::Bytes(hash)}.
/// Field ordering follows ECF canonical sort (shorter encoded keys first, then
/// lexicographic). Used to construct the params entity for collection/store
/// builtins whose fields are all `system/hash`-typed.
fn build_typed_args_entity(
    entity_type: &str,
    args: &[(String, entity_hash::Hash)],
) -> Result<Entity, ComputeError> {
    let sorted = canonical_sorted_pairs(args);
    let fields: Vec<(Value, Value)> = sorted
        .iter()
        .map(|(name, hash)| {
            (
                Value::Text(name.clone()),
                Value::Bytes(hash.to_bytes().to_vec()),
            )
        })
        .collect();
    let data = Value::Map(fields);
    Entity::new(entity_type, entity_ecf::to_ecf(&data)).map_err(|e| {
        ComputeError::InvalidExpression(format!(
            "build {} args entity: {}",
            entity_type, e
        ))
    })
}

/// Resolve a hash to a string value by evaluating the referenced expression.
/// Returns `""` (empty) on missing/non-string — the downstream inline
/// evaluator's validation will reject the empty/unknown op.
fn resolve_string_arg(
    args: &[(String, entity_hash::Hash)],
    key: &str,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> String {
    let hash = match args.iter().find(|(k, _)| k == key) {
        Some((_, h)) => *h,
        None => return String::new(),
    };
    let target = match ctx.resolve_or_error(&hash, key) {
        Ok(e) => e,
        Err(_) => return String::new(),
    };
    let v = eval::evaluate(&target, scope, budget, ctx);
    v.as_str_val().map(|s| s.to_string()).unwrap_or_default()
}

fn args_hash<'a>(args: &'a [(String, entity_hash::Hash)], key: &str) -> Option<&'a entity_hash::Hash> {
    args.iter().find(|(k, _)| k == key).map(|(_, h)| h)
}

fn alias_arithmetic(
    args: &[(String, entity_hash::Hash)],
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let op = resolve_string_arg(args, "op", scope, budget, ctx);
    let left = match args_hash(args, "left") {
        Some(h) => *h,
        None => return ComputeError::InvalidExpression("arithmetic alias: missing 'left'".into()).to_value(),
    };
    let right = match args_hash(args, "right") {
        Some(h) => *h,
        None => return ComputeError::InvalidExpression("arithmetic alias: missing 'right'".into()).to_value(),
    };
    let data = entity_ecf::cbor_map! {
        "left" => Value::Bytes(left.to_bytes().to_vec()),
        "op" => entity_ecf::text(&op),
        "right" => Value::Bytes(right.to_bytes().to_vec())
    };
    let arith = match Entity::new(TYPE_ARITHMETIC, entity_ecf::to_ecf(&data)) {
        Ok(e) => e,
        Err(_) => return ComputeError::InvalidExpression("arithmetic alias build".into()).to_value(),
    };
    eval::evaluate(&arith, scope, budget, ctx)
}

fn alias_compare(
    args: &[(String, entity_hash::Hash)],
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let op = resolve_string_arg(args, "op", scope, budget, ctx);
    let left = match args_hash(args, "left") {
        Some(h) => *h,
        None => return ComputeError::InvalidExpression("compare alias: missing 'left'".into()).to_value(),
    };
    let right = match args_hash(args, "right") {
        Some(h) => *h,
        None => return ComputeError::InvalidExpression("compare alias: missing 'right'".into()).to_value(),
    };
    let data = entity_ecf::cbor_map! {
        "left" => Value::Bytes(left.to_bytes().to_vec()),
        "op" => entity_ecf::text(&op),
        "right" => Value::Bytes(right.to_bytes().to_vec())
    };
    let cmp = match Entity::new(TYPE_COMPARE, entity_ecf::to_ecf(&data)) {
        Ok(e) => e,
        Err(_) => return ComputeError::InvalidExpression("compare alias build".into()).to_value(),
    };
    eval::evaluate(&cmp, scope, budget, ctx)
}

fn alias_logic(
    args: &[(String, entity_hash::Hash)],
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let op = resolve_string_arg(args, "op", scope, budget, ctx);
    let left = match args_hash(args, "left") {
        Some(h) => *h,
        None => return ComputeError::InvalidExpression("logic alias: missing 'left'".into()).to_value(),
    };
    let mut fields: Vec<(Value, Value)> = vec![
        (Value::Text("left".into()), Value::Bytes(left.to_bytes().to_vec())),
        (Value::Text("op".into()), entity_ecf::text(&op)),
    ];
    if let Some(right) = args_hash(args, "right") {
        fields.push((Value::Text("right".into()), Value::Bytes(right.to_bytes().to_vec())));
    }
    // ECF canonical sort.
    fields.sort_by(|(a, _), (b, _)| {
        let a_bytes = entity_ecf::to_ecf(a);
        let b_bytes = entity_ecf::to_ecf(b);
        a_bytes.len().cmp(&b_bytes.len()).then(a_bytes.cmp(&b_bytes))
    });
    let logic = match Entity::new(TYPE_LOGIC, entity_ecf::to_ecf(&Value::Map(fields))) {
        Ok(e) => e,
        Err(_) => return ComputeError::InvalidExpression("logic alias build".into()).to_value(),
    };
    eval::evaluate(&logic, scope, budget, ctx)
}

fn alias_field(
    args: &[(String, entity_hash::Hash)],
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let name = resolve_string_arg(args, "name", scope, budget, ctx);
    let entity_h = match args_hash(args, "entity") {
        Some(h) => *h,
        None => return ComputeError::InvalidExpression("field alias: missing 'entity'".into()).to_value(),
    };
    let data = entity_ecf::cbor_map! {
        "name" => entity_ecf::text(&name),
        "entity" => Value::Bytes(entity_h.to_bytes().to_vec())
    };
    let fld = match Entity::new(TYPE_FIELD, entity_ecf::to_ecf(&data)) {
        Ok(e) => e,
        Err(_) => return ComputeError::InvalidExpression("field alias build".into()).to_value(),
    };
    eval::evaluate(&fld, scope, budget, ctx)
}

fn alias_store(
    args: &[(String, entity_hash::Hash)],
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    // SA-2 per-field encoding for system/compute/store-args:
    //   - path  (system/tree/path / primitive-like) → resolve+evaluate to string
    //   - value (system/hash)                       → keep hash bytes; the
    //     store builtin's body evaluates it per SA-9
    let path = resolve_string_arg(args, "path", scope, budget, ctx);
    if path.is_empty() {
        return ComputeError::InvalidExpression(
            "store alias: missing or non-string 'path'".into(),
        )
        .to_value();
    }
    let value = match args_hash(args, "value") {
        Some(h) => *h,
        None => {
            return ComputeError::InvalidExpression("store alias: missing 'value'".into())
                .to_value()
        }
    };
    let data = entity_ecf::cbor_map! {
        "path" => entity_ecf::text(&path),
        "value" => Value::Bytes(value.to_bytes().to_vec())
    };
    let store_args = match Entity::new(TYPE_STORE_ARGS, entity_ecf::to_ecf(&data)) {
        Ok(e) => e,
        Err(_) => {
            return ComputeError::InvalidExpression("store alias: build args entity".into())
                .to_value()
        }
    };
    match dispatch_builtin(BUILTIN_STORE, "eval", &store_args, scope, budget, ctx) {
        Some(v) => v,
        None => ComputeError::InvalidExpression("store builtin dispatch failed".into()).to_value(),
    }
}

fn alias_construct(
    args: &[(String, entity_hash::Hash)],
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let entity_type = resolve_string_arg(args, "entity_type", scope, budget, ctx);
    if entity_type.is_empty() {
        return ComputeError::InvalidExpression(
            "construct alias: missing or empty 'entity_type'".into(),
        )
        .to_value();
    }
    // Treat every other arg as a named field of the constructed entity. Match
    // Go's `builtinConstruct` shape: caller passes each field hash under its
    // field name in args, alongside the reserved `entity_type`.
    let field_pairs: Vec<(String, entity_hash::Hash)> = args
        .iter()
        .filter(|(k, _)| k != "entity_type")
        .map(|(k, h)| (k.clone(), *h))
        .collect();
    let sorted_fields = canonical_sorted_pairs(&field_pairs);
    let fields_map: Vec<(Value, Value)> = sorted_fields
        .iter()
        .map(|(name, hash)| {
            (
                Value::Text(name.clone()),
                Value::Bytes(hash.to_bytes().to_vec()),
            )
        })
        .collect();
    let data = entity_ecf::cbor_map! {
        "entity_type" => entity_ecf::text(&entity_type),
        "fields" => Value::Map(fields_map)
    };
    let ctor = match Entity::new(TYPE_CONSTRUCT, entity_ecf::to_ecf(&data)) {
        Ok(e) => e,
        Err(_) => return ComputeError::InvalidExpression("construct alias build".into()).to_value(),
    };
    eval::evaluate(&ctor, scope, budget, ctx)
}

/// Dispatch to a builtin handler. Returns None if the path is not a builtin.
pub fn dispatch_builtin(
    path: &str,
    _operation: &str,
    params: &Entity,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> Option<ComputeValue> {
    let bare = extract_bare_builtin(path)?;

    let data = match decode_data(params) {
        Some(d) => d,
        None => return Some(ComputeError::InvalidExpression("Cannot decode builtin params".into()).to_value()),
    };

    let result = match bare {
        "arithmetic" => dispatch_arithmetic(&data, scope, budget, ctx),
        "compare" => dispatch_compare(&data, scope, budget, ctx),
        "logic" => dispatch_logic(&data, scope, budget, ctx),
        "field" => dispatch_field(&data, scope, budget, ctx),
        "construct" => dispatch_construct(&data, scope, budget, ctx),
        "map" => dispatch_map(&data, scope, budget, ctx),
        "filter" => dispatch_filter(&data, scope, budget, ctx),
        "fold" => dispatch_fold(&data, scope, budget, ctx),
        "store" => dispatch_store(&data, scope, budget, ctx),
        _ => return None,
    };

    Some(result)
}

fn extract_bare_builtin(path: &str) -> Option<&str> {
    if let Some(rest) = path.strip_prefix(BUILTIN_PREFIX) {
        return Some(rest);
    }
    if let Some(idx) = path.find("/system/compute/builtins/") {
        return Some(&path[idx + "/system/compute/builtins/".len()..]);
    }
    None
}

// ---------------------------------------------------------------------------
// Inline-equivalent builtins
// ---------------------------------------------------------------------------

fn dispatch_arithmetic(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let op = match data_str(data, "op") {
        Some(o) => o,
        None => return ComputeError::InvalidExpression("arithmetic: missing 'op'".into()).to_value(),
    };
    let left = eval_ref(data, "left", "arithmetic left", scope, budget, ctx);
    if left.is_error() { return left; }
    let right = eval_ref(data, "right", "arithmetic right", scope, budget, ctx);
    if right.is_error() { return right; }
    apply_arithmetic(&op, &left, &right)
}

fn dispatch_compare(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let op = match data_str(data, "op") {
        Some(o) => o,
        None => return ComputeError::InvalidExpression("compare: missing 'op'".into()).to_value(),
    };
    let left = eval_ref(data, "left", "compare left", scope, budget, ctx);
    if left.is_error() { return left; }
    let right = eval_ref(data, "right", "compare right", scope, budget, ctx);
    if right.is_error() { return right; }
    apply_compare(&op, &left, &right)
}

fn dispatch_logic(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let op = match data_str(data, "op") {
        Some(o) => o,
        None => return ComputeError::InvalidExpression("logic: missing 'op'".into()).to_value(),
    };
    let left = eval_ref(data, "left", "logic left", scope, budget, ctx);
    if left.is_error() { return left; }

    match op.as_str() {
        "not" => ComputeValue::Primitive(Value::Bool(!left.is_truthy())),
        "and" => {
            let right = eval_ref(data, "right", "logic right", scope, budget, ctx);
            if right.is_error() { return right; }
            ComputeValue::Primitive(Value::Bool(left.is_truthy() && right.is_truthy()))
        }
        "or" => {
            let right = eval_ref(data, "right", "logic right", scope, budget, ctx);
            if right.is_error() { return right; }
            ComputeValue::Primitive(Value::Bool(left.is_truthy() || right.is_truthy()))
        }
        _ => ComputeError::InvalidExpression(format!("Unknown logic op: {}", op)).to_value(),
    }
}

fn dispatch_field(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let name = match data_str(data, "name") {
        Some(n) => n,
        None => return ComputeError::InvalidExpression("field: missing 'name'".into()).to_value(),
    };
    let target = eval_ref(data, "entity", "field target", scope, budget, ctx);
    if target.is_error() { return target; }

    match &target {
        ComputeValue::Entity(e) => {
            let entity_data = match decode_data(e) {
                Some(d) => d,
                None => return ComputeError::TypeMismatch("Field access requires decodable entity data".into()).to_value(),
            };
            match entity_data.get(&name) {
                Some(v) => ComputeValue::Primitive(v.clone()),
                None => ComputeError::NotFound(format!("Field not found: {}", name)).to_value(),
            }
        }
        ComputeValue::Primitive(Value::Map(_)) => {
            match target.as_primitive().unwrap().get(&name) {
                Some(v) => ComputeValue::Primitive(v.clone()),
                None => ComputeError::NotFound(format!("Field not found: {}", name)).to_value(),
            }
        }
        _ => ComputeError::TypeMismatch("Field access requires entity or map".into()).to_value(),
    }
}

fn dispatch_construct(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let entity_type = match data_str(data, "entity_type") {
        Some(t) => t,
        None => return ComputeError::InvalidExpression("construct: missing 'entity_type'".into()).to_value(),
    };

    let fields = match data_hash_map(data, "fields") {
        Some(f) => f,
        None => return ComputeError::InvalidExpression("construct: missing 'fields'".into()).to_value(),
    };

    // §3.5 inline-vs-handler-form equivalence: the builtin handler form
    // (`system/compute/builtins/construct`) MUST produce the same content
    // hash as the inline `compute/construct`. To guarantee that, this
    // handler form just rebuilds the equivalent inline construct entity
    // and re-evaluates through `eval_construct` — one code path, no
    // duplicate encoder to drift. (Same shape as `alias_construct`.)
    let sorted = canonical_sorted_pairs(&fields);
    let fields_map: Vec<(Value, Value)> = sorted
        .iter()
        .map(|(name, hash)| {
            (
                Value::Text(name.clone()),
                Value::Bytes(hash.to_bytes().to_vec()),
            )
        })
        .collect();
    let construct_data = entity_ecf::cbor_map! {
        "entity_type" => entity_ecf::text(&entity_type),
        "fields" => Value::Map(fields_map)
    };
    let construct_entity =
        match Entity::new(TYPE_CONSTRUCT, entity_ecf::to_ecf(&construct_data)) {
            Ok(e) => e,
            Err(_) => {
                return ComputeError::InvalidExpression(
                    "construct: failed to build construct entity".into(),
                )
                .to_value()
            }
        };
    eval::evaluate(&construct_entity, scope, budget, ctx)
}

// ---------------------------------------------------------------------------
// Collection builtins (MUST-given-COMPUTE per v3.14 §10.1)
// ---------------------------------------------------------------------------

fn dispatch_map(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let collection = eval_ref(data, "collection", "map collection", scope, budget, ctx);
    if collection.is_error() { return collection; }
    let fn_val = eval_ref(data, "fn", "map fn", scope, budget, ctx);
    if fn_val.is_error() { return fn_val; }

    let items = match &collection {
        ComputeValue::Primitive(Value::Array(arr)) => arr.clone(),
        _ => return ComputeError::TypeMismatch("map: collection must be an array".into()).to_value(),
    };

    let closure = match extract_closure(&fn_val) {
        Some(c) => c,
        None => return ComputeError::TypeMismatch("map: fn must be a closure".into()).to_value(),
    };

    let mut results = Vec::new();
    for item in &items {
        let val = apply_closure_to_value(&closure, item, scope, budget, ctx);
        if val.is_error() { return val; }
        results.push(compute_value_to_cbor(&val));
    }

    ComputeValue::Primitive(Value::Array(results))
}

fn dispatch_filter(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let collection = eval_ref(data, "collection", "filter collection", scope, budget, ctx);
    if collection.is_error() { return collection; }
    let fn_val = eval_ref(data, "fn", "filter fn", scope, budget, ctx);
    if fn_val.is_error() { return fn_val; }

    let items = match &collection {
        ComputeValue::Primitive(Value::Array(arr)) => arr.clone(),
        _ => return ComputeError::TypeMismatch("filter: collection must be an array".into()).to_value(),
    };

    let closure = match extract_closure(&fn_val) {
        Some(c) => c,
        None => return ComputeError::TypeMismatch("filter: fn must be a closure".into()).to_value(),
    };

    let mut results = Vec::new();
    for item in &items {
        let val = apply_closure_to_value(&closure, item, scope, budget, ctx);
        if val.is_error() { return val; }
        if val.is_truthy() {
            results.push(item.clone());
        }
    }

    ComputeValue::Primitive(Value::Array(results))
}

fn dispatch_fold(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let collection = eval_ref(data, "collection", "fold collection", scope, budget, ctx);
    if collection.is_error() { return collection; }
    let fn_val = eval_ref(data, "fn", "fold fn", scope, budget, ctx);
    if fn_val.is_error() { return fn_val; }
    let initial = eval_ref(data, "initial", "fold initial", scope, budget, ctx);
    if initial.is_error() { return initial; }

    let items = match &collection {
        ComputeValue::Primitive(Value::Array(arr)) => arr.clone(),
        _ => return ComputeError::TypeMismatch("fold: collection must be an array".into()).to_value(),
    };

    let closure = match extract_closure(&fn_val) {
        Some(c) => c,
        None => return ComputeError::TypeMismatch("fold: fn must be a closure".into()).to_value(),
    };

    if closure.params.len() != 2 {
        return ComputeError::InvalidExpression("fold: fn must take 2 parameters (acc, item)".into()).to_value();
    }

    let mut acc = initial;
    for item in &items {
        let item_val = ComputeValue::Primitive(item.clone());
        acc = apply_closure_to_two_values(&closure, &acc, &item_val, scope, budget, ctx);
        if acc.is_error() { return acc; }
    }

    acc
}

// ---------------------------------------------------------------------------
// Store builtin (§3.5 SA-9 + SA-10, §6.2 — impure, capability check)
// ---------------------------------------------------------------------------

/// `store` builtin per §3.5:
/// - **SA-9.** The `value` field is an expression to evaluate (not a raw
///   entity at a literal hash). The evaluated result is what gets written.
///   A bare-primitive result is wrapped in `primitive/any`.
/// - **SA-10.** Implementations dispatch the write via `system/tree:put`
///   so capability/history/cascade are uniform. The spec explicitly allows
///   "a direct capability-checked emit" as equally compliant; this impl
///   takes that path — the §6.2 capability check is performed inline before
///   the content-store + location-index write.
/// - §6.2 capability gate: `store` MUST check the caller's capability covers
///   `system/tree:put` for the target path before writing.
fn dispatch_store(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let path = match data_str(data, "path") {
        Some(p) => p,
        None => return ComputeError::InvalidExpression("store: missing 'path'".into()).to_value(),
    };

    // §6.2 capability check (must precede write — see §3.5 SA-11: only `store`
    // is install-time auth-gated; here we enforce the runtime gate).
    if let Some(cap) = ctx.capability {
        if !entity_capability::check_permission(
            "put",
            &format!("/{}/system/tree", ctx.local_peer_id),
            ctx.local_peer_id,
            Some(&entity_capability::ResourceTarget {
                targets: vec![path.clone()],
                exclude: vec![],
            }),
            cap,
            ctx.local_peer_id,
        ) {
            return ComputeError::PermissionDenied(
                format!("Capability does not cover write: {}", path),
            ).to_value();
        }
    }

    let value_hash = match data_hash(data, "value") {
        Some(h) => h,
        None => return ComputeError::InvalidExpression("store: missing 'value'".into()).to_value(),
    };

    // SA-9: resolve the value hash and evaluate the referenced expression.
    // The stored entity is the EVALUATION RESULT, not the entity at the hash.
    let value_expr = match ctx.resolve_or_error(&value_hash, "store value") {
        Ok(e) => e,
        Err(err) => return err,
    };
    let evaluated = eval::evaluate(&value_expr, scope, budget, ctx);
    if evaluated.is_error() {
        return evaluated;
    }

    // SA-9: convert the evaluation result to an entity. Bare primitives wrap
    // in primitive/any; entity values pass through; closures serialize via
    // their canonical entity form.
    let to_store = match evaluated {
        ComputeValue::Entity(e) => e,
        ComputeValue::Closure(c) => c.to_entity(),
        ComputeValue::Primitive(v) => {
            let data_bytes = entity_ecf::to_ecf(&v);
            match Entity::new("primitive/any", data_bytes) {
                Ok(e) => e,
                Err(_) => return ComputeError::InvalidExpression(
                    "store: failed to wrap primitive result".into()
                ).to_value(),
            }
        }
        ComputeValue::Uint(u) => {
            let data_bytes = entity_ecf::to_ecf(&Value::Integer(ciborium::value::Integer::from(u)));
            match Entity::new("primitive/any", data_bytes) {
                Ok(e) => e,
                Err(_) => return ComputeError::InvalidExpression(
                    "store: failed to wrap uint result".into()
                ).to_value(),
            }
        }
        ComputeValue::Error(err) => return err.to_value(),
    };

    let qualified = qualify_path(&path, ctx.local_peer_id);

    let hash = match ctx.content_store.put(to_store) {
        Ok(h) => h,
        Err(_) => return ComputeError::InvalidExpression("store: failed to store entity".into()).to_value(),
    };

    ctx.location_index.set(&qualified, hash);

    ComputeValue::Primitive(Value::Bool(true))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn eval_ref(
    data: &Value,
    key: &str,
    label: &str,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let hash = match data_hash(data, key) {
        Some(h) => h,
        None => return ComputeError::InvalidExpression(format!("Missing hash field '{}'", key)).to_value(),
    };

    let target = match ctx.resolve_or_error(&hash, label) {
        Ok(e) => e,
        Err(err) => return err,
    };

    eval::evaluate(&target, scope, budget, ctx)
}

fn canonical_sorted_pairs(pairs: &[(String, Hash)]) -> Vec<(String, Hash)> {
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|(a, _), (b, _)| {
        let a_len = entity_ecf::to_ecf(&Value::Text(a.clone())).len();
        let b_len = entity_ecf::to_ecf(&Value::Text(b.clone())).len();
        a_len.cmp(&b_len).then_with(|| a.as_bytes().cmp(b.as_bytes()))
    });
    sorted
}

fn compute_value_to_cbor(value: &ComputeValue) -> Value {
    match value {
        ComputeValue::Primitive(v) => v.clone(),
        ComputeValue::Entity(e) => Value::Bytes(e.content_hash.to_bytes().to_vec()),
        ComputeValue::Closure(c) => Value::Bytes(c.to_entity().content_hash.to_bytes().to_vec()),
        ComputeValue::Error(err) => Value::Bytes(err.to_entity().content_hash.to_bytes().to_vec()),
        ComputeValue::Uint(u) => Value::Integer(ciborium::value::Integer::from(*u)),
    }
}

fn extract_closure(val: &ComputeValue) -> Option<ClosureValue> {
    match val {
        ComputeValue::Closure(c) => Some(c.clone()),
        ComputeValue::Entity(e) if e.entity_type == TYPE_CLOSURE => {
            let data = decode_data(e)?;
            let params = data_str_array(&data, "params")?;
            let body = data_hash(&data, "body")?;
            let env = data_hash(&data, "env");
            Some(ClosureValue { params, body, env })
        }
        _ => None,
    }
}

fn apply_closure_to_value(
    closure: &ClosureValue,
    item: &Value,
    _scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    if closure.params.is_empty() {
        return ComputeError::InvalidExpression("Closure must have at least one parameter".into()).to_value();
    }

    // v3.19b: use the shared kind-tagged eager load_scope. The prior duplicate
    // in this module silently round-tripped every binding as Primitive(v) and
    // is what caused the `v319_n5_closure_field` cross-impl regression.
    let mut scope = match crate::eval::load_scope_kind_tagged(&closure.env, ctx) {
        Ok(s) => s,
        Err(err) => return err.to_value(),
    };
    scope.set(closure.params[0].clone(), ComputeValue::Primitive(item.clone()));

    let body = match ctx.resolve(&closure.body) {
        Some(e) => e,
        None => return ComputeError::NotFound("Cannot resolve closure body".into()).to_value(),
    };

    eval::evaluate(&body, &scope, budget, ctx)
}

fn apply_closure_to_two_values(
    closure: &ClosureValue,
    first: &ComputeValue,
    second: &ComputeValue,
    _scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    if closure.params.len() < 2 {
        return ComputeError::InvalidExpression("Closure must have at least two parameters".into()).to_value();
    }

    let mut scope = match crate::eval::load_scope_kind_tagged(&closure.env, ctx) {
        Ok(s) => s,
        Err(err) => return err.to_value(),
    };
    scope.set(closure.params[0].clone(), first.clone());
    scope.set(closure.params[1].clone(), second.clone());

    let body = match ctx.resolve(&closure.body) {
        Some(e) => e,
        None => return ComputeError::NotFound("Cannot resolve closure body".into()).to_value(),
    };

    eval::evaluate(&body, &scope, budget, ctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};
    use std::collections::HashMap;

    const TEST_PID: &str = "testpeer123456789012345678901234567890123456";

    fn make_literal_int(n: i64) -> Entity {
        let data = entity_ecf::cbor_map! {
            "value" => entity_ecf::integer(n)
        };
        Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
    }

    #[test]
    fn test_builtin_arithmetic() {
        let cs = MemoryContentStore::new();
        let li = MemoryLocationIndex::new();
        let included = HashMap::new();

        let left = make_literal_int(3);
        let right = make_literal_int(4);
        let lh = cs.put(left).unwrap();
        let rh = cs.put(right).unwrap();

        let params_data = entity_ecf::cbor_map! {
            "left" => Value::Bytes(lh.to_bytes().to_vec()),
            "op" => entity_ecf::text("add"),
            "right" => Value::Bytes(rh.to_bytes().to_vec())
        };
        let params = Entity::new(TYPE_ARITHMETIC, entity_ecf::to_ecf(&params_data)).unwrap();

        let mut budget = Budget::default_budget();
        let mut ctx = EvalContext::new(&cs, &li, &included, TEST_PID);
        let result = dispatch_builtin(
            BUILTIN_ARITHMETIC, "eval", &params, &Scope::new(), &mut budget, &mut ctx,
        );

        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(val.as_i128(), Some(7));
    }

    #[test]
    fn test_builtin_compare() {
        let cs = MemoryContentStore::new();
        let li = MemoryLocationIndex::new();
        let included = HashMap::new();

        let left = make_literal_int(5);
        let right = make_literal_int(5);
        let lh = cs.put(left).unwrap();
        let rh = cs.put(right).unwrap();

        let params_data = entity_ecf::cbor_map! {
            "left" => Value::Bytes(lh.to_bytes().to_vec()),
            "op" => entity_ecf::text("eq"),
            "right" => Value::Bytes(rh.to_bytes().to_vec())
        };
        let params = Entity::new(TYPE_COMPARE, entity_ecf::to_ecf(&params_data)).unwrap();

        let mut budget = Budget::default_budget();
        let mut ctx = EvalContext::new(&cs, &li, &included, TEST_PID);
        let result = dispatch_builtin(
            BUILTIN_COMPARE, "eval", &params, &Scope::new(), &mut budget, &mut ctx,
        ).unwrap();

        match result {
            ComputeValue::Primitive(Value::Bool(b)) => assert!(b),
            _ => panic!("expected bool"),
        }
    }

    #[test]
    fn test_builtin_store_with_lookup_hash_value() {
        // SA-9: store evaluates the value expression. To store a pre-existing
        // entity at a path, the value field must reference a compute
        // expression that evaluates to the entity — `compute/lookup/hash` is
        // the canonical way. Evaluating it returns the resolved entity
        // (compute is a compute type so it can carry the hash through
        // `resolve`); store writes that entity.
        let cs = MemoryContentStore::new();
        let li = MemoryLocationIndex::new();
        let included = HashMap::new();

        // The actual data entity we want stored at the target path.
        let target_entity = Entity::new("app/data", entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "x" => entity_ecf::integer(42)
        })).unwrap();
        let target_hash = cs.put(target_entity.clone()).unwrap();

        // Authorize the lookup_hash target via the sealed authorized set so
        // resolve() will return the non-compute entity per §4.2 Tier 2.
        let mut authorized = std::collections::HashSet::new();
        authorized.insert(target_hash);

        // Wrap the hash in a compute/lookup/hash expression so SA-9's evaluate
        // step yields the entity (not a 404 from the non-compute-type guard).
        let lookup_data = entity_ecf::cbor_map! {
            "hash" => Value::Bytes(target_hash.to_bytes().to_vec())
        };
        let lookup_expr = Entity::new(TYPE_LOOKUP_HASH, entity_ecf::to_ecf(&lookup_data)).unwrap();
        let lookup_hash = cs.put(lookup_expr).unwrap();

        let params_data = entity_ecf::cbor_map! {
            "path" => entity_ecf::text("app/test/stored"),
            "value" => Value::Bytes(lookup_hash.to_bytes().to_vec())
        };
        let params = Entity::new("system/compute/store-args", entity_ecf::to_ecf(&params_data)).unwrap();

        let mut budget = Budget::default_budget();
        let mut ctx = EvalContext::new(&cs, &li, &included, TEST_PID)
            .with_authorized_hashes(authorized);
        let result = dispatch_builtin(
            BUILTIN_STORE, "eval", &params, &Scope::new(), &mut budget, &mut ctx,
        ).unwrap();

        assert!(result.is_truthy());
        let stored_path = format!("/{}/app/test/stored", TEST_PID);
        let stored_hash = li.get(&stored_path).expect("path bound");
        // SA-9: stored entity matches the lookup target.
        assert_eq!(stored_hash, target_hash);
    }

    #[test]
    fn test_builtin_store_with_primitive_value_wraps_primitive_any() {
        // SA-9: bare-primitive evaluation result is wrapped in primitive/any.
        let cs = MemoryContentStore::new();
        let li = MemoryLocationIndex::new();
        let included = HashMap::new();

        // value expression = compute/literal { value: 42 }
        let lit_data = entity_ecf::cbor_map! { "value" => entity_ecf::integer(42) };
        let lit = Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&lit_data)).unwrap();
        let lit_hash = cs.put(lit).unwrap();

        let params_data = entity_ecf::cbor_map! {
            "path" => entity_ecf::text("app/primitive/at"),
            "value" => Value::Bytes(lit_hash.to_bytes().to_vec())
        };
        let params = Entity::new("system/compute/store-args", entity_ecf::to_ecf(&params_data)).unwrap();

        let mut budget = Budget::default_budget();
        let mut ctx = EvalContext::new(&cs, &li, &included, TEST_PID);
        let result = dispatch_builtin(
            BUILTIN_STORE, "eval", &params, &Scope::new(), &mut budget, &mut ctx,
        ).unwrap();

        assert!(result.is_truthy());
        let stored_path = format!("/{}/app/primitive/at", TEST_PID);
        let stored_hash = li.get(&stored_path).expect("path bound");
        let stored_entity = cs.get(&stored_hash).expect("entity present");
        // SA-9 wrap target.
        assert_eq!(stored_entity.entity_type, "primitive/any");
    }

    #[test]
    fn test_not_a_builtin() {
        let cs = MemoryContentStore::new();
        let li = MemoryLocationIndex::new();
        let included = HashMap::new();

        let params = Entity::new("test", entity_ecf::to_ecf(&entity_ecf::cbor_map!{})).unwrap();
        let mut budget = Budget::default_budget();
        let mut ctx = EvalContext::new(&cs, &li, &included, TEST_PID);

        assert!(dispatch_builtin(
            "system/tree", "get", &params, &Scope::new(), &mut budget, &mut ctx,
        ).is_none());
    }

    #[test]
    fn test_is_builtin_path() {
        assert!(is_builtin_path("system/compute/builtins/arithmetic"));
        assert!(is_builtin_path(&format!("/{}/system/compute/builtins/store", TEST_PID)));
        assert!(!is_builtin_path("system/tree"));
    }
}
