//! CBOR Value utilities.
//!
//! Helper functions and extension traits for working with ciborium::Value.

use ciborium::Value;

/// Extension trait for ciborium::Value to provide map-like accessors.
pub trait ValueExt {
    /// Get a value by string key (for maps).
    fn get(&self, key: &str) -> Option<&Value>;

    /// Get a mutable value by string key (for maps).
    fn get_mut(&mut self, key: &str) -> Option<&mut Value>;

    /// Get as string.
    fn as_str(&self) -> Option<&str>;

    /// Get as u64.
    fn as_u64(&self) -> Option<u64>;

    /// Get as i64.
    fn as_i64(&self) -> Option<i64>;

    /// Get as bool.
    fn as_bool_val(&self) -> Option<bool>;

    /// Get as array.
    fn as_array(&self) -> Option<&Vec<Value>>;

    /// Get as bytes.
    fn as_bytes(&self) -> Option<&[u8]>;

    /// Check if null.
    fn is_null(&self) -> bool;

    /// Get as mutable map for modification.
    fn as_map_mut(&mut self) -> Option<&mut Vec<(Value, Value)>>;
}

impl ValueExt for Value {
    fn get(&self, key: &str) -> Option<&Value> {
        if let Value::Map(map) = self {
            for (k, v) in map {
                if let Value::Text(s) = k {
                    if s == key {
                        return Some(v);
                    }
                }
            }
        }
        None
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        if let Value::Map(map) = self {
            for (k, v) in map {
                if let Value::Text(s) = k {
                    if s == key {
                        return Some(v);
                    }
                }
            }
        }
        None
    }

    fn as_str(&self) -> Option<&str> {
        if let Value::Text(s) = self {
            Some(s)
        } else {
            None
        }
    }

    fn as_u64(&self) -> Option<u64> {
        if let Value::Integer(i) = self {
            u64::try_from(*i).ok()
        } else {
            None
        }
    }

    fn as_i64(&self) -> Option<i64> {
        if let Value::Integer(i) = self {
            i64::try_from(*i).ok()
        } else {
            None
        }
    }

    fn as_bool_val(&self) -> Option<bool> {
        if let Value::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    fn as_array(&self) -> Option<&Vec<Value>> {
        if let Value::Array(arr) = self {
            Some(arr)
        } else {
            None
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        if let Value::Bytes(b) = self {
            Some(b)
        } else {
            None
        }
    }

    fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    fn as_map_mut(&mut self) -> Option<&mut Vec<(Value, Value)>> {
        if let Value::Map(map) = self {
            Some(map)
        } else {
            None
        }
    }
}

/// Create a CBOR text value.
pub fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// Create a CBOR integer value.
pub fn integer(n: i64) -> Value {
    Value::Integer(ciborium::value::Integer::from(n))
}

/// Create a CBOR bool value.
pub fn bool_val(b: bool) -> Value {
    Value::Bool(b)
}

/// Create a CBOR array value.
pub fn array(items: Vec<Value>) -> Value {
    Value::Array(items)
}

/// Create a CBOR bytes value.
pub fn bytes(b: impl Into<Vec<u8>>) -> Value {
    Value::Bytes(b.into())
}

/// Create a CBOR null value.
pub fn null() -> Value {
    Value::Null
}

/// Default value for CBOR (empty map).
pub fn default_map() -> Value {
    Value::Map(vec![])
}

/// Create a CBOR map from an iterator of (String, Value) pairs.
pub fn map_from_iter(iter: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::Map(
        iter.into_iter()
            .map(|(k, v)| (Value::Text(k), v))
            .collect(),
    )
}

/// Insert a key-value pair into a CBOR map.
pub fn map_insert(map: &mut Value, key: impl Into<String>, value: Value) {
    if let Value::Map(m) = map {
        let key_val = Value::Text(key.into());
        m.retain(|(k, _)| k != &key_val);
        m.push((key_val, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor_map;

    #[test]
    fn test_value_get() {
        let map = cbor_map! {
            "name" => text("Alice"),
            "age" => integer(30)
        };

        assert_eq!(map.get("name").and_then(|v| v.as_str()), Some("Alice"));
        assert_eq!(map.get("age").and_then(|v| v.as_u64()), Some(30));
        assert!(map.get("missing").is_none());
    }

    #[test]
    fn test_map_insert() {
        let mut map = cbor_map! {
            "a" => integer(1)
        };

        map_insert(&mut map, "b", integer(2));
        assert_eq!(map.get("b").and_then(|v| v.as_u64()), Some(2));

        map_insert(&mut map, "a", integer(10));
        assert_eq!(map.get("a").and_then(|v| v.as_u64()), Some(10));
    }
}
