//! Entity Canonical Form (ECF) — deterministic CBOR encoding.
//!
//! ECF implements RFC 8949 Section 4.2 deterministic encoding for the
//! Entity Core Protocol. All implementations MUST produce identical
//! ECF bytes for semantically identical data.

mod encoder;
mod value;

pub use encoder::{
    ecf_for_hash, ecf_for_hash_value, encode_cbor_bstr, encode_cbor_text, encode_cbor_uint,
    encode_head, to_ecf,
};
pub use value::{
    array, bool_val, bytes, default_map, integer, map_from_iter, map_insert, null, text, ValueExt,
};

// Re-export ciborium::Value as our canonical CBOR value type.
pub use ciborium::Value;

/// Create a CBOR map from key-value pairs.
///
/// # Examples
///
/// ```
/// use entity_ecf::{cbor_map, integer, text};
///
/// let empty = cbor_map!{};
/// let map = cbor_map!{
///     "name" => text("Alice"),
///     "age" => integer(30)
/// };
/// ```
#[macro_export]
macro_rules! cbor_map {
    () => {
        $crate::Value::Map(vec![])
    };
    ($($key:expr => $value:expr),+ $(,)?) => {
        $crate::Value::Map(vec![
            $(($crate::Value::Text($key.into()), $value)),+
        ])
    };
}
