//! Entity-body formatting for `cat`.
//!
//! CBOR-decode-and-pretty-print with hex fallback. Lifted from
//! egui's `src/format.rs`. Kept crate-side so consumers don't each
//! need to wire their own pretty-printer to display entity bodies.

use std::fmt::Write;

/// Format an entity's data as a readable string. Tries CBOR decode
/// first, falls back to hex dump.
pub fn entity_data(data: &[u8]) -> String {
    match ciborium::from_reader::<ciborium::Value, _>(data) {
        Ok(value) => {
            let mut buf = String::new();
            cbor(&value, 0, &mut buf);
            buf
        }
        Err(_) => {
            let hex: String = data
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            format!("(raw {} bytes) {}", data.len(), hex)
        }
    }
}

/// Format a CBOR value as a human-readable string with indentation.
pub fn cbor(value: &ciborium::Value, depth: usize, buf: &mut String) {
    let indent = "  ".repeat(depth);
    match value {
        ciborium::Value::Text(s) => {
            let _ = write!(buf, "\"{}\"", s);
        }
        ciborium::Value::Integer(n) => {
            let _ = write!(buf, "{}", i128::from(*n));
        }
        ciborium::Value::Bool(b) => {
            let _ = write!(buf, "{}", b);
        }
        ciborium::Value::Null => {
            buf.push_str("null");
        }
        ciborium::Value::Bytes(b) => {
            if b.len() <= 8 {
                let hex: String = b.iter().map(|byte| format!("{:02x}", byte)).collect();
                let _ = write!(buf, "h'{}'", hex);
            } else {
                let hex: String =
                    b.iter().take(8).map(|byte| format!("{:02x}", byte)).collect();
                let _ = write!(buf, "h'{}...' ({} bytes)", hex, b.len());
            }
        }
        ciborium::Value::Array(arr) => {
            if arr.is_empty() {
                buf.push_str("[]");
            } else {
                buf.push_str("[\n");
                for (i, item) in arr.iter().enumerate() {
                    let _ = write!(buf, "{}  ", indent);
                    cbor(item, depth + 1, buf);
                    if i < arr.len() - 1 {
                        buf.push(',');
                    }
                    buf.push('\n');
                }
                let _ = write!(buf, "{}]", indent);
            }
        }
        ciborium::Value::Map(map) => {
            if map.is_empty() {
                buf.push_str("{}");
            } else {
                buf.push_str("{\n");
                for (i, (k, v)) in map.iter().enumerate() {
                    let _ = write!(buf, "{}  ", indent);
                    if let ciborium::Value::Text(key) = k {
                        let _ = write!(buf, "\"{}\": ", key);
                    } else {
                        cbor(k, depth + 1, buf);
                        buf.push_str(": ");
                    }
                    cbor(v, depth + 1, buf);
                    if i < map.len() - 1 {
                        buf.push(',');
                    }
                    buf.push('\n');
                }
                let _ = write!(buf, "{}}}", indent);
            }
        }
        _ => {
            buf.push_str("<other>");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_data_pretty_prints_cbor_map() {
        let mut bytes = Vec::new();
        let mut pairs = Vec::new();
        pairs.push((
            ciborium::Value::Text("name".into()),
            ciborium::Value::Text("alice".into()),
        ));
        ciborium::into_writer(&ciborium::Value::Map(pairs), &mut bytes).unwrap();
        let out = entity_data(&bytes);
        assert!(out.contains("\"name\": \"alice\""), "got: {}", out);
    }

    #[test]
    fn entity_data_falls_back_to_hex_for_non_cbor() {
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let out = entity_data(&bytes);
        assert!(out.starts_with("(raw 9 bytes)"), "got: {}", out);
    }
}
