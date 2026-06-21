//! Entity construction and field access: `compute/field`, `compute/construct`.
//!
//! `eval_field` reads a single field from an entity- or map-typed value.
//! `eval_construct` builds a new entity from `entity_type` and a `fields`
//! map of hash-referenced sub-expressions; field ordering follows the ECF
//! canonical sort (length, then lexical) so the produced bytes are stable
//! across implementations.

use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;

use crate::types::*;

use super::{canonical_sorted_pairs, eval_hash_ref, evaluate, EvalContext};

pub(super) fn eval_field(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let name = match data_str(data, "name") {
        Some(n) => n,
        None => {
            return ComputeError::InvalidExpression("compute/field missing 'name'".into())
                .to_value()
        }
    };

    let target = eval_hash_ref(data, "entity", "field target", scope, budget, ctx);
    if target.is_error() {
        return target;
    }

    extract_field(&name, &target, ctx)
}

/// Extract a single field from a target value.
///
/// **v3.19c α + N3 ruling (arch `6e73d3d`).** Two cases:
///
///   1. **In-flight** — the target `Entity` was just produced by `compute/construct`
///      in *this* eval. Its hash is in `ctx.constructed_in_flight`, and the
///      original typed `ComputeValue` per field is recorded there. We return
///      the typed value (e.g. `ComputeValue::Entity` for an entity-valued field),
///      so chains like `field(field(construct(…),"inner"),"name")` compose.
///
///   2. **Read-back / hand-built** — any other entity (read from the tree,
///      received over the wire, hand-built outside compute). Per N3 we
///      **return the bare data** — `Primitive(Bytes(<hash>))` for an entity-
///      valued field; the caller follows the ref via an explicit
///      `compute/lookup/hash`. **No shape-sniffing, no auto-resolve heuristic**
///      (the prior "33-byte ⇒ resolve" heuristic was the shape-sniff class N3
///      forbids — misfires on a real 33-byte bytes value).
fn extract_field(name: &str, target: &ComputeValue, ctx: &mut EvalContext<'_>) -> ComputeValue {
    if let ComputeValue::Entity(e) = target {
        // Case 1 — in-flight: this entity was constructed in *this* eval; the
        // typed field values are still around. Use them directly.
        if let Some(typed_value) = ctx
            .constructed_in_flight
            .get(&e.content_hash)
            .and_then(|m| m.get(name).cloned())
        {
            return typed_value;
        }
    }

    // Case 2 — read-back / hand-built: return the bare data per N3.
    let raw = match target {
        ComputeValue::Entity(e) => {
            let entity_data = match decode_data(e) {
                Some(d) => d,
                None => {
                    return ComputeError::TypeMismatch(
                        "Field access requires an entity with decodable data".into(),
                    )
                    .to_value()
                }
            };
            match entity_data.get(name) {
                Some(v) => v.clone(),
                None => {
                    return ComputeError::NotFound(format!("Field not found: {}", name)).to_value()
                }
            }
        }
        ComputeValue::Primitive(Value::Map(_)) => {
            match target.as_primitive().unwrap().get(name) {
                Some(v) => v.clone(),
                None => {
                    return ComputeError::NotFound(format!("Field not found: {}", name)).to_value()
                }
            }
        }
        _ => {
            return ComputeError::TypeMismatch(
                "Field access requires an entity with data, got non-entity value".into(),
            )
            .to_value()
        }
    };

    // Return raw value as-is (Primitive). The caller follows a `system/hash`
    // field via explicit `compute/lookup/hash`; we do NOT shape-sniff bytes
    // length nor try to resolve a hash heuristically (N3).
    ComputeValue::Primitive(raw)
}

/// Evaluate `compute/index` (§2.2). Returns the element at the (evaluated)
/// `index` of the (evaluated) `array`. Pure, core, override-prohibited.
/// - Negative or out-of-range index → `index_out_of_range`.
/// - `null` or non-array `array` → `type_mismatch`.
pub(super) fn eval_index(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let array_val = eval_hash_ref(data, "array", "index array", scope, budget, ctx);
    if array_val.is_error() {
        return array_val;
    }
    let index_val = eval_hash_ref(data, "index", "index index", scope, budget, ctx);
    if index_val.is_error() {
        return index_val;
    }

    let items = match array_value_as_slice(&array_val) {
        Some(items) => items,
        None => {
            return ComputeError::TypeMismatch(
                "compute/index requires array operand".into(),
            )
            .to_value()
        }
    };

    let idx_i128 = match index_val.as_i128() {
        Some(i) => i,
        None => {
            return ComputeError::TypeMismatch(
                "compute/index requires integer index".into(),
            )
            .to_value()
        }
    };

    if idx_i128 < 0 {
        return ComputeError::IndexOutOfRange(format!(
            "negative index {} (no from-end indexing)",
            idx_i128
        ))
        .to_value();
    }
    let len = items.len() as i128;
    if idx_i128 >= len {
        return ComputeError::IndexOutOfRange(format!(
            "index {} >= length {}",
            idx_i128, len
        ))
        .to_value();
    }

    ComputeValue::Primitive(items[idx_i128 as usize].clone())
}

/// Evaluate `compute/length` (§2.2). Returns the element count of the
/// (evaluated) `array`. Pure, core, override-prohibited.
/// - Empty array → `0`.
/// - `null` or non-array → `type_mismatch`.
pub(super) fn eval_length(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let array_val = eval_hash_ref(data, "array", "length array", scope, budget, ctx);
    if array_val.is_error() {
        return array_val;
    }

    let items = match array_value_as_slice(&array_val) {
        Some(items) => items,
        None => {
            return ComputeError::TypeMismatch(
                "compute/length requires array operand".into(),
            )
            .to_value()
        }
    };

    ComputeValue::Primitive(entity_ecf::integer(items.len() as i64))
}

/// Borrow the inner slice if the value is a CBOR array (`null` and any other
/// type return `None`, which the caller turns into `type_mismatch`).
fn array_value_as_slice(value: &ComputeValue) -> Option<&[Value]> {
    match value {
        ComputeValue::Primitive(Value::Array(items)) => Some(items),
        _ => None,
    }
}

pub(super) fn eval_construct(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let entity_type = match data_str(data, "entity_type") {
        Some(t) => t,
        None => {
            return ComputeError::InvalidExpression(
                "compute/construct missing 'entity_type'".into(),
            )
            .to_value()
        }
    };

    let fields = match data_hash_map(data, "fields") {
        Some(f) => f,
        None => {
            return ComputeError::InvalidExpression("compute/construct missing 'fields'".into())
                .to_value()
        }
    };

    let sorted_fields = canonical_sorted_pairs(&fields);

    // v3.19c α + N3 ruling (arch 6e73d3d): each field is encoded into its
    // bare V7 §1.4 form for the materialized data — entity-/closure-/error-
    // valued fields → bare `system/hash` byte string (with the referenced
    // entity ensured resident in the content store); primitive/record →
    // inline; `Uint` strips its cast tag (§2.2 rule 11). The materialized
    // entity is byte-identical to a hand-built (`Entity::new`) equivalent.
    //
    // Alongside the materialized form, this loop **also records the original
    // typed `ComputeValue` per field** in a per-eval `constructed_in_flight`
    // side-table (populated below). That's what `extract_field` consults when
    // an in-flight chain like `field(field(construct(…),"inner"),"name")`
    // composes — it finds the original `ComputeValue::Entity` for "inner"
    // typed, not the bare hash bytes. Once eval ends and a constructed entity
    // is re-read in a later eval, the side-table no longer has it → extract
    // returns the bare hash and the caller follows it via `compute/lookup/hash`
    // (per N3: no shape-sniff, no auto-resolve heuristic).
    let mut result_fields: Vec<(Value, Value)> = Vec::new();
    let mut in_flight_fields: std::collections::HashMap<String, ComputeValue> =
        std::collections::HashMap::new();
    for (name, hash) in &sorted_fields {
        let target = match ctx.resolve_or_error(hash, &format!("construct field {}", name)) {
            Ok(e) => e,
            Err(err) => return err,
        };
        let value = evaluate(&target, scope, budget, ctx);
        if value.is_error() {
            return value;
        }
        let cbor_val = encode_construct_field_bare(&value, ctx);
        // Strip the ephemeral cast tag at the binding boundary (§2.2 rule 11)
        // so the in-flight typed value matches the materialized one.
        in_flight_fields.insert(name.clone(), crate::types::strip_cast_tag(value));
        result_fields.push((Value::Text(name.clone()), cbor_val));
    }

    let result_data = Value::Map(result_fields);
    let data_bytes = entity_ecf::to_ecf(&result_data);

    let materialized = match Entity::new(&entity_type, data_bytes) {
        Ok(e) => e,
        Err(err) => {
            return ComputeError::InvalidExpression(format!("Failed to create entity: {}", err))
                .to_value()
        }
    };
    // Make the just-constructed entity resident in the content store so the
    // hash is dedup-stable with a hand-built equivalent (this is what makes
    // `lookup/hash` work after the eval boundary).
    let _ = ctx.content_store.put(materialized.clone());
    ctx.encountered
        .insert(materialized.content_hash, materialized.clone());
    // Record the original typed field values for in-flight chain composition
    // (v3.19c α + N3 ruling). After this eval ends, the side-table is gone;
    // a re-read of `materialized` from a later eval will navigate via bare
    // V7 §1.4 (return-the-hash, explicit lookup/hash to follow).
    ctx.constructed_in_flight
        .insert(materialized.content_hash, in_flight_fields);
    ComputeValue::Entity(materialized)
}

/// Encode a single construct field's evaluated value into its bare V7 §1.4
/// form: entity / closure / error → bare `system/hash` content reference
/// (the entity's `content_hash` bytes — algorithm || digest, variable-length
/// per V7 §1.2; entity made resident in the content store); primitive /
/// record → inlined bare CBOR; `Uint` strips its cast tag (§2.2 rule 11).
///
/// This is the "materialize-at-encode" half of v3.19c α — the constructed
/// entity's data fields are bare per V7 §1.4 from the moment of construction,
/// so the constructed entity's `content_hash` equals the hand-built equivalent
/// (`Entity::new` + the same encoded data) byte-for-byte.
fn encode_construct_field_bare(value: &ComputeValue, ctx: &mut EvalContext<'_>) -> Value {
    match value {
        ComputeValue::Entity(e) => {
            // V7 §1.4: entity references are `system/hash` byte strings. Make
            // the entity resident so navigation can resolve it.
            let _ = ctx.content_store.put(e.clone());
            ctx.encountered.insert(e.content_hash, e.clone());
            Value::Bytes(e.content_hash.to_bytes().to_vec())
        }
        ComputeValue::Closure(c) => {
            let e = c.to_entity();
            let h = e.content_hash;
            let _ = ctx.content_store.put(e.clone());
            ctx.encountered.insert(h, e);
            Value::Bytes(h.to_bytes().to_vec())
        }
        ComputeValue::Error(err) => {
            let e = err.to_entity();
            let h = e.content_hash;
            let _ = ctx.content_store.put(e.clone());
            ctx.encountered.insert(h, e);
            Value::Bytes(h.to_bytes().to_vec())
        }
        ComputeValue::Primitive(v) => v.clone(),
        ComputeValue::Uint(u) => {
            // §2.2 rule 11: strip cast tag at the construct field boundary.
            Value::Integer(ciborium::value::Integer::from(*u as i64))
        }
    }
}
