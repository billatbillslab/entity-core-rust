//! EntityCbor — CBOR diagnostic + Variant<->ECF utilities for Godot.

use ciborium::value::Integer as CborInt;
use ciborium::Value;
use entity_ecf::to_ecf;
use godot::prelude::*;

/// Maximum recursion depth for `encode_variant` / `decode_to_variant`.
///
/// Defense against adversarial CBOR (or pathological Variant graphs) blowing
/// the stack. Real entity payloads do not exceed a handful of nesting levels.
const MAX_DEPTH: u32 = 64;

/// CBOR utility class providing diagnostic + Variant<->CBOR conversion.
///
/// All methods are static — no instances needed.
#[derive(GodotClass)]
#[class(base=RefCounted)]
pub struct EntityCbor {
    base: Base<RefCounted>,
}

#[godot_api]
impl IRefCounted for EntityCbor {
    fn init(base: Base<RefCounted>) -> Self {
        Self { base }
    }
}

#[godot_api]
impl EntityCbor {
    /// Encode a CBOR value to diagnostic notation string (RFC 8949 §8).
    #[func]
    fn to_diag(data: PackedByteArray) -> GString {
        let bytes = data.to_vec();
        match cbor_diag::parse_bytes(&bytes) {
            Ok(val) => {
                let s = val.to_diag_pretty();
                GString::from(s.as_str())
            }
            Err(e) => {
                godot_error!("EntityCbor: decode error: {}", e);
                GString::new()
            }
        }
    }

    /// Parse CBOR diagnostic notation into bytes.
    #[func]
    fn from_diag(diag: GString) -> PackedByteArray {
        match cbor_diag::parse_diag(&diag.to_string()) {
            Ok(val) => {
                let bytes = val.to_bytes();
                let mut result = PackedByteArray::new();
                result.extend(bytes.into_iter());
                result
            }
            Err(e) => {
                godot_error!("EntityCbor: parse error: {}", e);
                PackedByteArray::new()
            }
        }
    }

    /// Encode an ECF value from type + data to bytes.
    #[func]
    fn encode_text(text: GString) -> PackedByteArray {
        let val = entity_ecf::text(&text.to_string());
        let bytes = entity_ecf::to_ecf(&val);
        let mut result = PackedByteArray::new();
        result.extend(bytes.into_iter());
        result
    }

    /// Compute the content hash for a type + data pair.
    /// Returns 33-byte PackedByteArray.
    #[func]
    fn compute_hash(entity_type: GString, data: PackedByteArray) -> PackedByteArray {
        let hash = entity_hash::Hash::compute(&entity_type.to_string(), &data.to_vec());
        let bytes = hash.to_bytes();
        let mut result = PackedByteArray::new();
        result.extend(bytes.iter().copied());
        result
    }

    /// Encode a Godot Variant to ECF (deterministic CBOR per RFC 8949 §4.2).
    ///
    /// Supported Variant types:
    ///   Nil             -> CBOR null
    ///   Bool            -> CBOR true / false
    ///   Int             -> CBOR int (i64)
    ///   Float           -> CBOR float (f64)
    ///   String          -> CBOR text string
    ///   PackedByteArray -> CBOR byte string
    ///   Array           -> CBOR array (recursive)
    ///   Dictionary      -> CBOR map (text keys only; output keys sorted per ECF)
    ///
    /// Unsupported (Vector*, Color, StringName, NodePath, Object, Callable,
    /// Signal, etc.): callers should round-trip via a Dictionary convention
    /// (e.g. `{x, y}` for Vector2) before encoding.
    ///
    /// On failure: logs via `godot_error!` and returns an empty PackedByteArray.
    #[func]
    fn encode_variant(value: Variant) -> PackedByteArray {
        match variant_to_value(&value, 0) {
            Ok(v) => {
                let bytes = to_ecf(&v);
                let mut result = PackedByteArray::new();
                result.extend(bytes.into_iter());
                result
            }
            Err(e) => {
                godot_error!("EntityCbor::encode_variant: {}", e);
                PackedByteArray::new()
            }
        }
    }

    /// Decode ECF/CBOR bytes to a Godot Variant.
    ///
    /// Inverse of [`encode_variant`]. CBOR types map to:
    ///   null        -> Nil
    ///   true/false  -> Bool
    ///   int         -> int (clamped to i64 range with warning if exceeded)
    ///   float       -> float
    ///   text        -> String
    ///   bytes       -> PackedByteArray
    ///   array       -> Array (Variant entries, recursive)
    ///   map         -> Dictionary (recursive; map keys MUST be text strings)
    ///   tag         -> transparently decoded as its inner value
    ///
    /// On failure (malformed CBOR, non-text map keys, unsupported variants):
    /// logs via `godot_error!` and returns Nil.
    #[func]
    fn decode_to_variant(bytes: PackedByteArray) -> Variant {
        let raw = bytes.to_vec();
        let value: Value = match ciborium::de::from_reader(raw.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                godot_error!("EntityCbor::decode_to_variant: parse error: {}", e);
                return Variant::nil();
            }
        };
        match value_to_variant(&value, 0) {
            Ok(v) => v,
            Err(e) => {
                godot_error!("EntityCbor::decode_to_variant: {}", e);
                Variant::nil()
            }
        }
    }

    /// Symmetric alias for [`decode_to_variant`] — same semantics, name
    /// mirroring [`encode_variant`]. Prefer this in new callers.
    #[func]
    fn decode_variant(bytes: PackedByteArray) -> Variant {
        Self::decode_to_variant(bytes)
    }
}

/// Convert a Godot Variant into an ECF `Value`.
///
/// Recursion is bounded by [`MAX_DEPTH`]. Map keys are inserted as text
/// values; bytewise sorting is the encoder's job (see `to_ecf`).
fn variant_to_value(value: &Variant, depth: u32) -> Result<Value, String> {
    if depth > MAX_DEPTH {
        return Err(format!("recursion depth exceeded ({})", MAX_DEPTH));
    }
    let ty = value.get_type();
    match ty {
        VariantType::NIL => Ok(Value::Null),
        VariantType::BOOL => {
            let b = value
                .try_to::<bool>()
                .map_err(|e| format!("BOOL conversion failed: {}", e))?;
            Ok(Value::Bool(b))
        }
        VariantType::INT => {
            let i = value
                .try_to::<i64>()
                .map_err(|e| format!("INT conversion failed: {}", e))?;
            Ok(Value::Integer(i.into()))
        }
        VariantType::FLOAT => {
            let f = value
                .try_to::<f64>()
                .map_err(|e| format!("FLOAT conversion failed: {}", e))?;
            Ok(Value::Float(f))
        }
        VariantType::STRING => {
            let s = value
                .try_to::<GString>()
                .map_err(|e| format!("STRING conversion failed: {}", e))?;
            Ok(Value::Text(s.to_string()))
        }
        VariantType::PACKED_BYTE_ARRAY => {
            let pba = value
                .try_to::<PackedByteArray>()
                .map_err(|e| format!("PackedByteArray conversion failed: {}", e))?;
            Ok(Value::Bytes(pba.to_vec()))
        }
        VariantType::ARRAY => {
            let arr = value
                .try_to::<VarArray>()
                .map_err(|e| format!("Array conversion failed: {}", e))?;
            let mut out = Vec::with_capacity(arr.len());
            for item in arr.iter_shared() {
                out.push(variant_to_value(&item, depth + 1)?);
            }
            Ok(Value::Array(out))
        }
        VariantType::DICTIONARY => {
            let dict = value
                .try_to::<VarDictionary>()
                .map_err(|e| format!("Dictionary conversion failed: {}", e))?;
            let mut out: Vec<(Value, Value)> = Vec::with_capacity(dict.len());
            for (k, v) in dict.iter_shared() {
                if k.get_type() != VariantType::STRING {
                    return Err(format!(
                        "Dictionary key must be String (got {:?}); cross-impl interop requires text keys",
                        k.get_type()
                    ));
                }
                let key_str = k
                    .try_to::<GString>()
                    .map_err(|e| format!("Dictionary key STRING conversion failed: {}", e))?
                    .to_string();
                let val = variant_to_value(&v, depth + 1)?;
                out.push((Value::Text(key_str), val));
            }
            Ok(Value::Map(out))
        }
        other => Err(format!(
            "unsupported Variant type {:?}; encode via a Dictionary convention or omit",
            other
        )),
    }
}

/// Convert a ciborium `Value` back into a Godot Variant.
///
/// Tags are transparently unwrapped. Integers exceeding `i64` range are
/// clamped (saturated) with a `godot_warn!` — never silently wrapped.
fn value_to_variant(value: &Value, depth: u32) -> Result<Variant, String> {
    if depth > MAX_DEPTH {
        return Err(format!("recursion depth exceeded ({})", MAX_DEPTH));
    }
    match value {
        Value::Null => Ok(Variant::nil()),
        Value::Bool(b) => Ok(b.to_variant()),
        Value::Integer(i) => Ok(cbor_int_to_i64_clamped(*i).to_variant()),
        Value::Float(f) => Ok(f.to_variant()),
        Value::Text(s) => Ok(GString::from(s.as_str()).to_variant()),
        Value::Bytes(b) => {
            let mut pba = PackedByteArray::new();
            pba.extend(b.iter().copied());
            Ok(pba.to_variant())
        }
        Value::Array(items) => {
            let mut arr = VarArray::new();
            for item in items {
                arr.push(&value_to_variant(item, depth + 1)?);
            }
            Ok(arr.to_variant())
        }
        Value::Map(entries) => {
            let mut dict = VarDictionary::new();
            for (k, v) in entries {
                let key = match k {
                    Value::Text(s) => s.clone(),
                    other => {
                        return Err(format!(
                            "CBOR map key must be a text string; got {:?}",
                            cbor_kind(other)
                        ));
                    }
                };
                let val = value_to_variant(v, depth + 1)?;
                let _ = dict.insert(GString::from(key.as_str()), val);
            }
            Ok(dict.to_variant())
        }
        Value::Tag(_, inner) => value_to_variant(inner, depth + 1),
        other => Err(format!("unsupported CBOR variant: {:?}", cbor_kind(other))),
    }
}

/// Clamp a CBOR integer (which may exceed i64 range in either direction)
/// into i64, warning on overflow rather than silently wrapping.
fn cbor_int_to_i64_clamped(i: CborInt) -> i64 {
    if let Ok(n) = i64::try_from(i) {
        return n;
    }
    // CBOR integers can be u64 (positive) or "negative u64" (= -1 - u).
    // Probe positive side first.
    if let Ok(u) = u64::try_from(i) {
        godot_warn!(
            "EntityCbor::decode_to_variant: CBOR integer {} exceeds i64::MAX; clamped to i64::MAX",
            u
        );
        return i64::MAX;
    }
    godot_warn!(
        "EntityCbor::decode_to_variant: CBOR integer below i64::MIN; clamped to i64::MIN"
    );
    i64::MIN
}

/// One-word label for a `ciborium::Value` variant, for error messages.
fn cbor_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Integer(_) => "integer",
        Value::Float(_) => "float",
        Value::Bytes(_) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    //! Pure-Rust tests of the encoder/decoder using `ciborium::Value` directly.
    //!
    //! Variant-level round-trip is covered on the GDScript side (see the
    //! Godot project's `tests/integration/test_cbor_variant_roundtrip.gd`).
    //! godot::prelude::Variant cannot be constructed without an active
    //! Godot runtime, so the Rust-side tests focus on the ECF mapping and
    //! the decoder's error / clamp / depth behaviour.
    use super::*;

    #[test]
    fn encode_primitives_match_to_ecf() {
        for v in [
            Value::Null,
            Value::Bool(true),
            Value::Bool(false),
            Value::Integer(0.into()),
            Value::Integer(42i64.into()),
            Value::Integer((-1i64).into()),
            Value::Float(1.5),
            Value::Text("hi".into()),
            Value::Bytes(vec![1, 2, 3]),
        ] {
            let bytes = to_ecf(&v);
            let back: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(back, v, "ciborium round-trip changed value: {:?}", v);
        }
    }

    #[test]
    fn ecf_determinism_for_maps() {
        let a = Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]);
        let b = Value::Map(vec![
            (Value::Text("a".into()), Value::Integer(1.into())),
            (Value::Text("b".into()), Value::Integer(2.into())),
        ]);
        assert_eq!(
            to_ecf(&a),
            to_ecf(&b),
            "ECF encoding must be insertion-order independent"
        );
    }

    #[test]
    fn decode_rejects_non_text_map_keys() {
        let bad = Value::Map(vec![(Value::Integer(1.into()), Value::Integer(2.into()))]);
        let err = walk_for_errors(&bad).unwrap_err();
        assert!(err.contains("text string"), "unexpected error: {}", err);
    }

    #[test]
    fn decode_clamps_overlarge_positive_int() {
        let huge = u64::MAX;
        let clamped = cbor_int_to_i64_clamped(huge.into());
        assert_eq!(clamped, i64::MAX);
    }

    #[test]
    fn decode_clamps_overlarge_negative_int() {
        let very_neg: CborInt = i128::from(i64::MIN)
            .checked_sub(1)
            .unwrap()
            .try_into()
            .expect("CBOR integer accepts -2^63 - 1");
        let clamped = cbor_int_to_i64_clamped(very_neg);
        assert_eq!(clamped, i64::MIN);
    }

    #[test]
    fn decode_i64_boundary_values_unchanged() {
        for n in [i64::MIN, -1, 0, 1, i64::MAX] {
            let cbor: CborInt = n.into();
            assert_eq!(cbor_int_to_i64_clamped(cbor), n);
        }
    }

    #[test]
    fn decode_tag_is_transparent() {
        // to_ecf strips tags during encoding (see encoder.rs:95), so a
        // tagged Value encoded then re-decoded should equal its inner.
        // This pins the encoder behaviour our decoder relies on.
        let inner = Value::Text("payload".into());
        let tagged = Value::Tag(99, Box::new(inner.clone()));
        let bytes = to_ecf(&tagged);
        let back: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back, inner);
    }

    #[test]
    fn decode_depth_limit_trips() {
        let mut v = Value::Null;
        for _ in 0..(MAX_DEPTH + 2) {
            v = Value::Array(vec![v]);
        }
        let err = walk_for_errors(&v).unwrap_err();
        assert!(err.contains("recursion depth"), "got: {}", err);
    }

    #[test]
    fn cbor_kind_labels_each_variant() {
        assert_eq!(cbor_kind(&Value::Null), "null");
        assert_eq!(cbor_kind(&Value::Bool(true)), "bool");
        assert_eq!(cbor_kind(&Value::Integer(0.into())), "integer");
        assert_eq!(cbor_kind(&Value::Float(0.0)), "float");
        assert_eq!(cbor_kind(&Value::Bytes(vec![])), "bytes");
        assert_eq!(cbor_kind(&Value::Text(String::new())), "text");
        assert_eq!(cbor_kind(&Value::Array(vec![])), "array");
        assert_eq!(cbor_kind(&Value::Map(vec![])), "map");
        assert_eq!(
            cbor_kind(&Value::Tag(1, Box::new(Value::Null))),
            "tag"
        );
    }

    /// Mirror of `value_to_variant`'s control flow that returns `()` on
    /// success — exists because real `Variant` construction needs a live
    /// Godot runtime, which unit tests don't have. The error strings here
    /// MUST match `value_to_variant`'s (drift would silently invalidate
    /// the rejection tests).
    fn walk_for_errors(value: &Value) -> Result<(), String> {
        fn walk(value: &Value, depth: u32) -> Result<(), String> {
            if depth > MAX_DEPTH {
                return Err(format!("recursion depth exceeded ({})", MAX_DEPTH));
            }
            match value {
                Value::Map(entries) => {
                    for (k, v) in entries {
                        if !matches!(k, Value::Text(_)) {
                            return Err(format!(
                                "CBOR map key must be a text string; got {:?}",
                                cbor_kind(k)
                            ));
                        }
                        walk(v, depth + 1)?;
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        walk(item, depth + 1)?;
                    }
                }
                Value::Tag(_, inner) => walk(inner, depth + 1)?,
                _ => {}
            }
            Ok(())
        }
        walk(value, 0)
    }
}
