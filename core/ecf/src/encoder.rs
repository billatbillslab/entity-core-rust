//! ECF deterministic CBOR encoder.
//!
//! Implements RFC 8949 Section 4.2 deterministic encoding:
//! 1. Minimal integer encoding
//! 2. Map keys sorted by encoded byte length, then lexicographically
//! 3. Definite lengths only (no indefinite/streaming)
//! 4. Shortest float encoding preserving value

use ciborium::Value;
use std::cmp::Ordering;

/// CBOR major types
const MAJOR_UNSIGNED: u8 = 0 << 5;
const MAJOR_NEGATIVE: u8 = 1 << 5;
const MAJOR_BYTES: u8 = 2 << 5;
const MAJOR_TEXT: u8 = 3 << 5;
const MAJOR_ARRAY: u8 = 4 << 5;
const MAJOR_MAP: u8 = 5 << 5;
const MAJOR_SIMPLE: u8 = 7 << 5;

/// Simple values
const SIMPLE_FALSE: u8 = MAJOR_SIMPLE | 20;
const SIMPLE_TRUE: u8 = MAJOR_SIMPLE | 21;
const SIMPLE_NULL: u8 = MAJOR_SIMPLE | 22;

/// Float indicators
const FLOAT_HALF: u8 = MAJOR_SIMPLE | 25;
const FLOAT_SINGLE: u8 = MAJOR_SIMPLE | 26;
const FLOAT_DOUBLE: u8 = MAJOR_SIMPLE | 27;

/// Encode a ciborium::Value to Entity Canonical Form (deterministic CBOR).
///
/// This is the primary function for ECF encoding. The output bytes are
/// deterministic: the same input always produces the same output.
pub fn to_ecf(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();
    encode_value(&mut output, value);
    output
}

/// Encode `{type, data}` for hash computation, with raw CBOR bytes for data.
///
/// This is the primary hash-input function. It embeds `data` bytes directly
/// without re-encoding, preserving byte fidelity (matching Go's approach).
///
/// Produces:
/// ```cbor
/// {
///   "data": <raw_data_bytes>,
///   "type": <entity_type>
/// }
/// ```
///
/// Keys are sorted by encoded length then lexicographically:
/// "data" (4 chars) before "type" (4 chars) alphabetically.
pub fn ecf_for_hash(entity_type: &str, data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    // Map with 2 items
    output.push(MAJOR_MAP | 2);

    // Keys sorted: "data" before "type" (same length, lexicographic order)
    // "data" key
    encode_cbor_text(&mut output, "data");
    // Embed raw CBOR bytes directly — no re-encoding
    output.extend_from_slice(data);

    // "type" key
    encode_cbor_text(&mut output, "type");
    encode_cbor_text(&mut output, entity_type);

    output
}

/// Encode `{type, data}` for hash computation, with a Value for data.
///
/// Convenience variant that ECF-encodes the value first, then calls
/// [`ecf_for_hash`] with the resulting bytes.
pub fn ecf_for_hash_value(entity_type: &str, data: &Value) -> Vec<u8> {
    let encoded_data = to_ecf(data);
    ecf_for_hash(entity_type, &encoded_data)
}

/// Encode a CBOR value to ECF.
fn encode_value(output: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Null => output.push(SIMPLE_NULL),
        Value::Bool(b) => output.push(if *b { SIMPLE_TRUE } else { SIMPLE_FALSE }),
        Value::Integer(i) => encode_integer(output, *i),
        Value::Float(f) => encode_float(output, *f),
        Value::Bytes(b) => encode_cbor_bstr(output, b),
        Value::Text(s) => encode_cbor_text(output, s),
        Value::Array(arr) => encode_array(output, arr),
        Value::Map(map) => encode_map(output, map),
        Value::Tag(_, inner) => encode_value(output, inner),
        _ => output.push(SIMPLE_NULL),
    }
}

/// Encode a CBOR head (major type + argument) with minimal bytes.
///
/// The `major` byte is the pre-shifted major type (e.g., `0` for unsigned, `2 << 5` for bstr).
/// For public callers, use the convenience functions [`encode_cbor_text`], [`encode_cbor_bstr`],
/// and [`encode_cbor_uint`] instead.
pub fn encode_head(output: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        output.push(major | value as u8);
    } else if value <= 0xFF {
        output.push(major | 24);
        output.push(value as u8);
    } else if value <= 0xFFFF {
        output.push(major | 25);
        output.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xFFFF_FFFF {
        output.push(major | 26);
        output.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        output.push(major | 27);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

/// Encode a CBOR integer (can be positive or negative).
fn encode_integer(output: &mut Vec<u8>, i: ciborium::value::Integer) {
    if let Ok(u) = u64::try_from(i) {
        encode_head(output, MAJOR_UNSIGNED, u);
    } else if let Ok(n) = i64::try_from(i) {
        if n >= 0 {
            encode_head(output, MAJOR_UNSIGNED, n as u64);
        } else {
            // CBOR negative: encode -1-n
            encode_head(output, MAJOR_NEGATIVE, (-1 - n) as u64);
        }
    } else {
        // Very large integer — try i128
        let n: i128 = i.into();
        if n >= 0 {
            encode_head(output, MAJOR_UNSIGNED, n as u64);
        } else {
            encode_head(output, MAJOR_NEGATIVE, (-1 - n) as u64);
        }
    }
}

/// Encode a floating point number with shortest representation.
///
/// Per ECF spec: use the shortest encoding that preserves the value.
fn encode_float(output: &mut Vec<u8>, f: f64) {
    // Try half-precision (16-bit)
    if let Some(half_bits) = try_encode_half(f) {
        output.push(FLOAT_HALF);
        output.extend_from_slice(&half_bits.to_be_bytes());
        return;
    }

    // Try single-precision (32-bit)
    let single = f as f32;
    if (single as f64) == f {
        output.push(FLOAT_SINGLE);
        output.extend_from_slice(&single.to_bits().to_be_bytes());
        return;
    }

    // Fall back to double-precision (64-bit)
    output.push(FLOAT_DOUBLE);
    output.extend_from_slice(&f.to_bits().to_be_bytes());
}

/// Try to encode a float as half-precision (16-bit IEEE 754).
///
/// Returns the 16-bit representation if the value can be exactly represented,
/// None otherwise.
fn try_encode_half(f: f64) -> Option<u16> {
    if f == 0.0 {
        return Some(if f.is_sign_negative() { 0x8000 } else { 0x0000 });
    }

    if f.is_nan() {
        return Some(0x7E00);
    }

    if f.is_infinite() {
        return Some(if f.is_sign_positive() { 0x7C00 } else { 0xFC00 });
    }

    let half = f64_to_f16(f);
    let recovered = f16_to_f64(half);

    if recovered == f {
        Some(half)
    } else {
        None
    }
}

/// Convert f64 to IEEE 754 half-precision (16-bit).
fn f64_to_f16(f: f64) -> u16 {
    let bits = f.to_bits();
    let sign = ((bits >> 63) & 1) as u16;
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & 0xF_FFFF_FFFF_FFFF;

    if exp == 0x7FF {
        if frac == 0 {
            return (sign << 15) | 0x7C00;
        } else {
            return (sign << 15) | 0x7E00;
        }
    }

    let new_exp = exp - 1023 + 15;

    if new_exp >= 31 {
        return (sign << 15) | 0x7C00;
    }

    if new_exp <= 0 {
        if new_exp < -10 {
            return sign << 15;
        }
        let subnormal_frac = ((frac | 0x10_0000_0000_0000) >> (1 - new_exp + 42)) as u16;
        return (sign << 15) | subnormal_frac;
    }

    let half_frac = (frac >> 42) as u16;
    (sign << 15) | ((new_exp as u16) << 10) | half_frac
}

/// Convert IEEE 754 half-precision (16-bit) to f64.
fn f16_to_f64(bits: u16) -> f64 {
    let sign = (bits >> 15) & 1;
    let exp = (bits >> 10) & 0x1F;
    let frac = bits & 0x3FF;

    if exp == 0 {
        if frac == 0 {
            return if sign == 1 { -0.0 } else { 0.0 };
        }
        let value = (frac as f64) * 2.0_f64.powi(-24);
        return if sign == 1 { -value } else { value };
    }

    if exp == 31 {
        if frac == 0 {
            return if sign == 1 {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            };
        }
        return f64::NAN;
    }

    let exp64 = (exp as i32) - 15 + 1023;
    let frac64 = (frac as u64) << 42;
    let bits64 = ((sign as u64) << 63) | ((exp64 as u64) << 52) | frac64;
    f64::from_bits(bits64)
}

/// Encode a CBOR text string (major type 3, minimal encoding).
pub fn encode_cbor_text(output: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    encode_head(output, MAJOR_TEXT, bytes.len() as u64);
    output.extend_from_slice(bytes);
}

/// Encode a CBOR byte string (major type 2, minimal encoding).
pub fn encode_cbor_bstr(output: &mut Vec<u8>, bytes: &[u8]) {
    encode_head(output, MAJOR_BYTES, bytes.len() as u64);
    output.extend_from_slice(bytes);
}

/// Encode a CBOR unsigned integer (major type 0, minimal encoding).
pub fn encode_cbor_uint(output: &mut Vec<u8>, value: u64) {
    encode_head(output, MAJOR_UNSIGNED, value);
}

/// Encode an array.
fn encode_array(output: &mut Vec<u8>, arr: &[Value]) {
    encode_head(output, MAJOR_ARRAY, arr.len() as u64);
    for item in arr {
        encode_value(output, item);
    }
}

/// Encode a map with deterministic key ordering.
///
/// Keys are sorted by:
/// 1. Encoded byte length (shorter first)
/// 2. Lexicographically (by encoded bytes)
fn encode_map(output: &mut Vec<u8>, map: &[(Value, Value)]) {
    let mut entries: Vec<(Vec<u8>, &Value)> = map
        .iter()
        .map(|(k, v)| {
            let mut encoded_key = Vec::new();
            encode_value(&mut encoded_key, k);
            (encoded_key, v)
        })
        .collect();

    entries.sort_by(|a, b| match a.0.len().cmp(&b.0.len()) {
        Ordering::Equal => a.0.cmp(&b.0),
        other => other,
    });

    encode_head(output, MAJOR_MAP, map.len() as u64);

    for (encoded_key, value) in entries {
        output.extend_from_slice(&encoded_key);
        encode_value(output, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::{array, bool_val, integer, null, text};
    use crate::cbor_map;

    fn to_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn test_empty_map() {
        let ecf = to_ecf(&cbor_map! {});
        assert_eq!(ecf, vec![0xA0]);
    }

    #[test]
    fn test_single_uint() {
        let ecf = to_ecf(&cbor_map! {"value" => integer(42)});
        assert_eq!(to_hex(&ecf), "A1 65 76 61 6C 75 65 18 2A");
    }

    #[test]
    fn test_small_integers() {
        assert_eq!(to_ecf(&integer(0)), vec![0x00]);
        assert_eq!(to_ecf(&integer(1)), vec![0x01]);
        assert_eq!(to_ecf(&integer(23)), vec![0x17]);
        assert_eq!(to_ecf(&integer(24)), vec![0x18, 0x18]);
        assert_eq!(to_ecf(&integer(255)), vec![0x18, 0xFF]);
        assert_eq!(to_ecf(&integer(256)), vec![0x19, 0x01, 0x00]);
    }

    #[test]
    fn test_negative_integers() {
        assert_eq!(to_ecf(&integer(-1)), vec![0x20]);
        assert_eq!(to_ecf(&integer(-10)), vec![0x29]);
        assert_eq!(to_ecf(&integer(-100)), vec![0x38, 0x63]);
    }

    #[test]
    fn test_boolean() {
        assert_eq!(to_ecf(&bool_val(true)), vec![0xF5]);
        assert_eq!(to_ecf(&bool_val(false)), vec![0xF4]);
    }

    #[test]
    fn test_null() {
        assert_eq!(to_ecf(&null()), vec![0xF6]);
    }

    #[test]
    fn test_text_string() {
        assert_eq!(to_ecf(&text("")), vec![0x60]);
        let ecf = to_ecf(&text("hello"));
        assert_eq!(ecf, vec![0x65, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_array() {
        let ecf = to_ecf(&array(vec![integer(1), integer(2), integer(3)]));
        assert_eq!(ecf, vec![0x83, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_key_ordering_by_length() {
        let ecf = to_ecf(&cbor_map! {
            "z" => integer(1),
            "a" => integer(2),
            "bb" => integer(3),
            "aaa" => integer(4)
        });
        let expected = vec![
            0xA4,
            0x61, b'a', 0x02,
            0x61, b'z', 0x01,
            0x62, b'b', b'b', 0x03,
            0x63, b'a', b'a', b'a', 0x04,
        ];
        assert_eq!(ecf, expected);
    }

    #[test]
    fn test_ecf_for_hash_value_key_order() {
        let ecf = ecf_for_hash_value("test", &cbor_map! {"value" => integer(1)});
        assert_eq!(ecf[0], 0xA2);
        assert_eq!(&ecf[1..6], &[0x64, b'd', b'a', b't', b'a']);
    }

    #[test]
    fn test_ecf_for_hash_raw_bytes() {
        // ecf_for_hash with raw bytes should embed them directly
        let data_bytes = to_ecf(&cbor_map! {"value" => integer(1)});
        let from_raw = ecf_for_hash("test", &data_bytes);
        let from_value = ecf_for_hash_value("test", &cbor_map! {"value" => integer(1)});
        assert_eq!(from_raw, from_value);
    }

    #[test]
    fn test_float_half_precision() {
        let ecf = to_ecf(&Value::Float(1.0));
        assert_eq!(ecf, vec![0xF9, 0x3C, 0x00]);

        let ecf = to_ecf(&Value::Float(1.5));
        assert_eq!(ecf, vec![0xF9, 0x3E, 0x00]);

        let ecf = to_ecf(&Value::Float(0.0));
        assert_eq!(ecf, vec![0xF9, 0x00, 0x00]);
    }

    #[test]
    fn test_float_double_precision() {
        let ecf = to_ecf(&Value::Float(1.1));
        assert_eq!(ecf[0], 0xFB);
        assert_eq!(ecf.len(), 9);
    }

    #[test]
    fn test_spec_empty_map_hash() {
        let ecf = to_ecf(&cbor_map! {});
        assert_eq!(to_hex(&ecf), "A0");
    }

    #[test]
    fn test_spec_single_uint_encoding() {
        let ecf = to_ecf(&cbor_map! {"value" => integer(42)});
        assert_eq!(to_hex(&ecf), "A1 65 76 61 6C 75 65 18 2A");
    }

    #[test]
    fn test_spec_key_ordering() {
        let ecf = to_ecf(&cbor_map! {
            "z" => integer(1),
            "a" => integer(2),
            "bb" => integer(3),
            "aaa" => integer(4)
        });
        assert_eq!(
            to_hex(&ecf),
            "A4 61 61 02 61 7A 01 62 62 62 03 63 61 61 61 04"
        );
    }

    #[test]
    fn test_byte_string() {
        let ecf = to_ecf(&Value::Bytes(vec![0x01, 0x02, 0x03]));
        assert_eq!(ecf, vec![0x43, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_nested_map() {
        let ecf = to_ecf(&cbor_map! {
            "outer" => cbor_map! {
                "inner" => integer(1)
            }
        });
        // A1 = map(1), 65 "outer", A1 = map(1), 65 "inner", 01
        assert_eq!(
            to_hex(&ecf),
            "A1 65 6F 75 74 65 72 A1 65 69 6E 6E 65 72 01"
        );
    }
}
