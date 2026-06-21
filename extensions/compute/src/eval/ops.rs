//! Operator expressions: `compute/{arithmetic,compare,logic}` plus the pure
//! math helpers (`apply_arithmetic`, `apply_compare`) re-exported for use by
//! `builtins.rs`.
//!
//! The eval_* wrappers resolve hash-referenced operands via `eval_hash_ref`
//! and then delegate to the pure `apply_*` helpers — keeping the math in one
//! place and the I/O at the edge.

use ciborium::Value;

use crate::types::*;

use super::{eval_hash_ref, EvalContext};

pub(super) fn eval_arithmetic(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let op = match data_str(data, "op") {
        Some(o) => o,
        None => {
            return ComputeError::InvalidExpression("compute/arithmetic missing 'op'".into())
                .to_value()
        }
    };

    let left = eval_hash_ref(data, "left", "arithmetic left", scope, budget, ctx);
    if left.is_error() {
        return left;
    }
    let right = eval_hash_ref(data, "right", "arithmetic right", scope, budget, ctx);
    if right.is_error() {
        return right;
    }

    apply_arithmetic(&op, &left, &right)
}

pub(super) fn eval_compare(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let op = match data_str(data, "op") {
        Some(o) => o,
        None => {
            return ComputeError::InvalidExpression("compute/compare missing 'op'".into())
                .to_value()
        }
    };

    let left = eval_hash_ref(data, "left", "compare left", scope, budget, ctx);
    if left.is_error() {
        return left;
    }
    let right = eval_hash_ref(data, "right", "compare right", scope, budget, ctx);
    if right.is_error() {
        return right;
    }

    apply_compare(&op, &left, &right)
}

pub(super) fn eval_logic(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let op = match data_str(data, "op") {
        Some(o) => o,
        None => {
            return ComputeError::InvalidExpression("compute/logic missing 'op'".into()).to_value()
        }
    };

    let left = eval_hash_ref(data, "left", "logic left", scope, budget, ctx);
    if left.is_error() {
        return left;
    }

    match op.as_str() {
        "not" => ComputeValue::Primitive(Value::Bool(!left.is_truthy())),
        "and" => {
            let right = eval_hash_ref(data, "right", "logic right", scope, budget, ctx);
            if right.is_error() {
                return right;
            }
            ComputeValue::Primitive(Value::Bool(left.is_truthy() && right.is_truthy()))
        }
        "or" => {
            let right = eval_hash_ref(data, "right", "logic right", scope, budget, ctx);
            if right.is_error() {
                return right;
            }
            ComputeValue::Primitive(Value::Bool(left.is_truthy() || right.is_truthy()))
        }
        _ => ComputeError::InvalidExpression(format!("Unknown logic op: {}", op)).to_value(),
    }
}

/// Arithmetic operations (§2.2 rules 1, 3, 4, 5, 6, 8, 9, 10, 11).
///
/// - **Rule 1** (float promotion): `add`/`sub`/`mul`/`div` promote both
///   operands to f64 when either is float. `mod` is integer-only (rule 4).
/// - **Rule 3** (div promotion): integer `div` with exact result stays
///   integer; non-exact promotes to float.
/// - **Rule 4** (truncated mod, integer-only): sign of result matches the
///   dividend. `mod` with a float operand → `type_mismatch`.
/// - **Rule 5** (div-by-zero): integer → `division_by_zero`; float follows
///   IEEE 754.
/// - **Rule 6** (operand types): both operands MUST be numeric.
/// - **Rule 8** (sign-agnostic add/sub/mul): 64-bit two's-complement,
///   wrapping mod 2⁶⁴. Operands are read as a single 64-bit pattern (i64) —
///   no int/uint branch. `add(3, -1)` = `2`.
/// - **Rule 9** (div/mod/compare signed-default): signed unless an operand
///   carries a uint cast tag (rule 11) from an immediately-prior
///   `compute/numeric-cast → primitive/uint`, in which case unsigned.
/// - **Rule 10** (canonical wire encoding): integer arithmetic results
///   encoded by signed two's-complement interpretation — emitted as
///   `Value::Integer(i64)` so ciborium's sign-based encoding yields one
///   canonical wire form (bit 63 set → major type 1). Genuinely-unsigned
///   values produced by `numeric-cast → uint` use `ComputeValue::Uint`
///   which encodes as major type 0.
pub fn apply_arithmetic(op: &str, left: &ComputeValue, right: &ComputeValue) -> ComputeValue {
    // Rule 6
    if !left.is_numeric() || !right.is_numeric() {
        return ComputeError::TypeMismatch("Arithmetic requires numeric operands".into()).to_value();
    }

    // Rule 4: mod is integer-only. Reject float operands BEFORE rule 1's
    // float promotion (which applies to add/sub/mul/div, not mod).
    if op == "mod" && (left.is_float() || right.is_float()) {
        return ComputeError::TypeMismatch(
            "mod is integer-only; float operand not allowed (§2.2 rule 4)".into(),
        )
        .to_value();
    }

    // Rule 1: float promotion for add/sub/mul/div.
    if left.is_float() || right.is_float() {
        return apply_arithmetic_float(op, left, right);
    }

    // Both integers — sign-agnostic 64-bit two's-complement view.
    let l = left.as_i128().unwrap() as i64;
    let r = right.as_i128().unwrap() as i64;

    match op {
        // Rule 8: sign-agnostic; Rule 10: emit signed canonical encoding.
        "add" => ComputeValue::Primitive(entity_ecf::integer(l.wrapping_add(r))),
        "sub" => ComputeValue::Primitive(entity_ecf::integer(l.wrapping_sub(r))),
        "mul" => ComputeValue::Primitive(entity_ecf::integer(l.wrapping_mul(r))),
        // Rules 9 + 5 + 3: signed by default; unsigned when an operand is
        // uint-tagged (immediately preceded by numeric-cast → uint).
        "div" => apply_div_integer(left, right),
        "mod" => apply_mod_integer(left, right),
        _ => ComputeError::InvalidExpression(format!("Unknown arithmetic op: {}", op)).to_value(),
    }
}

fn apply_div_integer(left: &ComputeValue, right: &ComputeValue) -> ComputeValue {
    let unsigned = is_uint_tagged(left) || is_uint_tagged(right);
    if unsigned {
        let l = left.as_i128().unwrap() as u64;
        let r = right.as_i128().unwrap() as u64;
        if r == 0 {
            return ComputeError::DivisionByZero.to_value();
        }
        // Rule 3 applied with unsigned interpretation.
        if l % r == 0 {
            ComputeValue::Uint(l / r)
        } else {
            ComputeValue::Primitive(Value::Float(l as f64 / r as f64))
        }
    } else {
        let l = left.as_i128().unwrap() as i64;
        let r = right.as_i128().unwrap() as i64;
        if r == 0 {
            return ComputeError::DivisionByZero.to_value();
        }
        if l % r == 0 {
            // wrapping_div handles the i64::MIN / -1 overflow per rule 8 spirit.
            ComputeValue::Primitive(entity_ecf::integer(l.wrapping_div(r)))
        } else {
            ComputeValue::Primitive(Value::Float(l as f64 / r as f64))
        }
    }
}

fn apply_mod_integer(left: &ComputeValue, right: &ComputeValue) -> ComputeValue {
    let unsigned = is_uint_tagged(left) || is_uint_tagged(right);
    if unsigned {
        let l = left.as_i128().unwrap() as u64;
        let r = right.as_i128().unwrap() as u64;
        if r == 0 {
            return ComputeError::DivisionByZero.to_value();
        }
        ComputeValue::Uint(l % r)
    } else {
        let l = left.as_i128().unwrap() as i64;
        let r = right.as_i128().unwrap() as i64;
        if r == 0 {
            return ComputeError::DivisionByZero.to_value();
        }
        // Rule 4: truncated remainder — sign follows dividend.
        // i64::wrapping_rem matches: e.g. (-7).wrapping_rem(3) = -1.
        ComputeValue::Primitive(entity_ecf::integer(l.wrapping_rem(r)))
    }
}

fn apply_arithmetic_float(op: &str, left: &ComputeValue, right: &ComputeValue) -> ComputeValue {
    let l = left.to_f64().unwrap();
    let r = right.to_f64().unwrap();

    let result = match op {
        "add" => l + r,
        "sub" => l - r,
        "mul" => l * r,
        "div" => {
            if r == 0.0 {
                return ComputeValue::Primitive(Value::Float(l / r));
            }
            l / r
        }
        "mod" => {
            if r == 0.0 {
                return ComputeError::DivisionByZero.to_value();
            }
            l % r
        }
        _ => {
            return ComputeError::InvalidExpression(format!("Unknown arithmetic op: {}", op))
                .to_value()
        }
    };

    ComputeValue::Primitive(Value::Float(result))
}

/// Evaluate `compute/numeric-cast` (§2.2). Intra-numeric conversion only —
/// `to_type` ∈ {`primitive/int`, `primitive/uint`, `primitive/float`}.
///
/// - int ↔ uint: bit-reinterpret at 64-bit width.
/// - int/uint → float: native conversion; lossy above 2^53 is defined-not-error.
/// - float → int/uint: truncate toward zero; NaN/±Inf/out-of-range →
///   `cast_out_of_range`.
/// - non-numeric `value` or unrecognized `to_type` → `type_mismatch`.
pub(super) fn eval_numeric_cast(
    data: &Value,
    scope: &Scope,
    budget: &mut Budget,
    ctx: &mut EvalContext<'_>,
) -> ComputeValue {
    let to_type = match data_str(data, "to_type") {
        Some(t) => t,
        None => {
            return ComputeError::InvalidExpression(
                "compute/numeric-cast missing 'to_type'".into(),
            )
            .to_value()
        }
    };

    let value = super::eval_hash_ref(data, "value", "numeric-cast value", scope, budget, ctx);
    if value.is_error() {
        return value;
    }
    if !value.is_numeric() {
        return ComputeError::TypeMismatch(format!(
            "compute/numeric-cast 'value' must be numeric, got {:?}",
            describe_kind(&value)
        ))
        .to_value();
    }

    match to_type.as_str() {
        TYPE_PRIMITIVE_INT => cast_to_int(&value),
        TYPE_PRIMITIVE_UINT => cast_to_uint(&value),
        TYPE_PRIMITIVE_FLOAT => cast_to_float(&value),
        other => ComputeError::TypeMismatch(format!(
            "compute/numeric-cast 'to_type' must be one of primitive/{{int,uint,float}}, got {}",
            other
        ))
        .to_value(),
    }
}

fn cast_to_int(value: &ComputeValue) -> ComputeValue {
    // Per §2.2 rule 11: numeric-cast produces a value of the target
    // interpretation. `int` is the default — no separate tag is needed; the
    // bit pattern is emitted as `Primitive(Value::Integer(i64))` and encoded
    // canonically signed per rule 10.
    if value.is_float() {
        let f = value.as_f64().unwrap();
        if !f.is_finite() {
            return ComputeError::CastOutOfRange(format!(
                "float→int: non-finite value ({})",
                f
            ))
            .to_value();
        }
        let t = f.trunc();
        // i64::MIN as f64 is exactly representable (-9.2233720368547758e18); the
        // upper bound 2^63 (9.2233720368547758e18) is also exact but lies one
        // above i64::MAX, so use strict <.
        if t < i64::MIN as f64 || t >= 9_223_372_036_854_775_808.0 {
            return ComputeError::CastOutOfRange(format!(
                "float→int: out of range ({} → {})",
                f, t
            ))
            .to_value();
        }
        return ComputeValue::Primitive(entity_ecf::integer(t as i64));
    }
    // Integer source — reinterpret bit pattern at 64-bit width.
    let bits = value.as_i128().unwrap() as i64; // sign-agnostic reinterpret via i128 → i64
    ComputeValue::Primitive(entity_ecf::integer(bits))
}

fn cast_to_uint(value: &ComputeValue) -> ComputeValue {
    // Produces a Uint tag consumed by the immediately-following op (rule 11).
    if value.is_float() {
        let f = value.as_f64().unwrap();
        if !f.is_finite() {
            return ComputeError::CastOutOfRange(format!(
                "float→uint: non-finite value ({})",
                f
            ))
            .to_value();
        }
        let t = f.trunc();
        if t < 0.0 || t >= 18_446_744_073_709_551_616.0 {
            return ComputeError::CastOutOfRange(format!(
                "float→uint: out of range ({} → {})",
                f, t
            ))
            .to_value();
        }
        return ComputeValue::Uint(t as u64);
    }
    // Integer source — reinterpret bit pattern. Value::Integer with negative
    // value bits → u64 via `as i64 as u64` two-step keeps the bit pattern.
    let bits = value.as_i128().unwrap() as i64 as u64;
    ComputeValue::Uint(bits)
}

fn cast_to_float(value: &ComputeValue) -> ComputeValue {
    if value.is_float() {
        return value.clone();
    }
    // int/uint → float; lossy above 2^53 is defined, not an error.
    ComputeValue::Primitive(Value::Float(value.to_f64().unwrap()))
}

fn describe_kind(v: &ComputeValue) -> &'static str {
    match v {
        ComputeValue::Primitive(Value::Integer(_)) => "int",
        ComputeValue::Primitive(Value::Float(_)) => "float",
        ComputeValue::Primitive(Value::Text(_)) => "string",
        ComputeValue::Primitive(Value::Bool(_)) => "bool",
        ComputeValue::Primitive(Value::Null) => "null",
        ComputeValue::Primitive(Value::Bytes(_)) => "bytes",
        ComputeValue::Primitive(Value::Array(_)) => "array",
        ComputeValue::Primitive(Value::Map(_)) => "map",
        ComputeValue::Primitive(_) => "primitive",
        ComputeValue::Uint(_) => "uint",
        ComputeValue::Entity(_) => "entity",
        ComputeValue::Closure(_) => "closure",
        ComputeValue::Error(_) => "error",
    }
}

/// Comparison operations (§2.2 + §306 + rules 9 + 11).
///
/// `eq`/`neq`: incompatible types → false/true. Numeric cross-type comparison
/// via float promotion.
///
/// Ordering (`lt`/`gt`/`lte`/`gte`):
/// - String operands: lexicographic UTF-8 bytes.
/// - Mixed-with-float: float promotion.
/// - Integer operands: **signed-default** per rule 9. Switch to unsigned
///   interpretation when either operand carries a uint cast tag from an
///   immediately-prior `compute/numeric-cast → primitive/uint` (rule 11).
///   This is the WASM `gt_u`/`lt_u` role reached by explicit conversion.
pub fn apply_compare(op: &str, left: &ComputeValue, right: &ComputeValue) -> ComputeValue {
    match op {
        "eq" => ComputeValue::Primitive(Value::Bool(compute_values_equal(left, right))),
        "neq" => ComputeValue::Primitive(Value::Bool(!compute_values_equal(left, right))),
        "lt" | "gt" | "lte" | "gte" => {
            if left.is_numeric() && right.is_numeric() {
                if left.is_float() || right.is_float() {
                    let l = left.to_f64().unwrap();
                    let r = right.to_f64().unwrap();
                    let b = match op {
                        "lt" => l < r,
                        "gt" => l > r,
                        "lte" => l <= r,
                        "gte" => l >= r,
                        _ => unreachable!(),
                    };
                    return ComputeValue::Primitive(Value::Bool(b));
                }
                // Integer-integer ordering — rule 9 selects signedness.
                let b = if is_uint_tagged(left) || is_uint_tagged(right) {
                    let l = left.as_i128().unwrap() as u64;
                    let r = right.as_i128().unwrap() as u64;
                    match op {
                        "lt" => l < r,
                        "gt" => l > r,
                        "lte" => l <= r,
                        "gte" => l >= r,
                        _ => unreachable!(),
                    }
                } else {
                    let l = left.as_i128().unwrap() as i64;
                    let r = right.as_i128().unwrap() as i64;
                    match op {
                        "lt" => l < r,
                        "gt" => l > r,
                        "lte" => l <= r,
                        "gte" => l >= r,
                        _ => unreachable!(),
                    }
                };
                ComputeValue::Primitive(Value::Bool(b))
            } else if left.is_string() && right.is_string() {
                let l = left.as_str_val().unwrap();
                let r = right.as_str_val().unwrap();
                let b = match op {
                    "lt" => l.as_bytes() < r.as_bytes(),
                    "gt" => l.as_bytes() > r.as_bytes(),
                    "lte" => l.as_bytes() <= r.as_bytes(),
                    "gte" => l.as_bytes() >= r.as_bytes(),
                    _ => unreachable!(),
                };
                ComputeValue::Primitive(Value::Bool(b))
            } else {
                ComputeError::TypeMismatch(
                    "Ordering comparison requires numeric or string operands".into(),
                )
                .to_value()
            }
        }
        _ => ComputeError::InvalidExpression(format!("Unknown compare op: {}", op)).to_value(),
    }
}

/// Structural equality for compute values (v3.6 A2).
///
/// Numeric cross-type: eq(1, 1.0) → true (both promote to float for comparison).
/// Incompatible types → false.
fn compute_values_equal(a: &ComputeValue, b: &ComputeValue) -> bool {
    if a.is_numeric() && b.is_numeric() {
        if a.is_float() || b.is_float() {
            return a.to_f64() == b.to_f64();
        }
        return a.as_i128() == b.as_i128();
    }
    match (a, b) {
        (ComputeValue::Primitive(va), ComputeValue::Primitive(vb)) => {
            entity_ecf::to_ecf(va) == entity_ecf::to_ecf(vb)
        }
        (ComputeValue::Entity(ea), ComputeValue::Entity(eb)) => {
            ea.content_hash == eb.content_hash
        }
        (ComputeValue::Closure(ca), ComputeValue::Closure(cb)) => {
            ca.body == cb.body && ca.params == cb.params && ca.env == cb.env
        }
        _ => false,
    }
}
