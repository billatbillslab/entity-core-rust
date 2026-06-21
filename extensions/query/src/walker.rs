//! Hash and path reference extraction from entity data.
//!
//! The reverse hash index needs to find all `system/hash` values in entity data.
//! The path link index needs to find all `system/tree/path` values.

use entity_hash::Hash;
use entity_types::TypeRegistry;

/// Extract all system/hash references from entity data by scanning CBOR.
///
/// Walks the CBOR value tree recursively. Any byte string of length 33
/// with algorithm byte 0x00 is treated as a system/hash reference.
/// Returns (hash, field_name) pairs where field_name is the top-level
/// map key containing the reference.
pub fn extract_hash_refs(data: &[u8]) -> Vec<(Hash, String)> {
    let value: ciborium::Value = match ciborium::from_reader(data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut refs = Vec::new();

    // Entity data is always a CBOR map at the top level
    if let Some(entries) = value.as_map() {
        for (key, val) in entries {
            let field_name = key.as_text().unwrap_or("").to_string();
            collect_hashes(val, &field_name, &mut refs);
        }
    }

    refs
}

fn collect_hashes(value: &ciborium::Value, field_name: &str, out: &mut Vec<(Hash, String)>) {
    match value {
        ciborium::Value::Bytes(b) if b.len() == 33 && b[0] == 0x00 => {
            if let Ok(hash) = Hash::from_bytes(b) {
                out.push((hash, field_name.to_string()));
            }
        }
        ciborium::Value::Array(arr) => {
            for item in arr {
                collect_hashes(item, field_name, out);
            }
        }
        ciborium::Value::Map(map) => {
            for (_, v) in map {
                collect_hashes(v, field_name, out);
            }
        }
        _ => {}
    }
}

/// Extract all system/tree/path references using type-aware walking.
///
/// Looks up the entity type in the TypeRegistry, walks fields according
/// to their FieldSpec, and collects string values from fields declared
/// as `type_ref: "system/tree/path"`.
///
/// Returns (path_value, field_name) pairs.
pub fn extract_path_refs(
    data: &[u8],
    entity_type: &str,
    type_registry: &TypeRegistry,
) -> Vec<(String, String)> {
    let type_def = match type_registry.get(entity_type) {
        Some(td) => td,
        None => return Vec::new(),
    };

    let value: ciborium::Value = match ciborium::from_reader(data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let map = match value.as_map() {
        Some(m) => m,
        None => return Vec::new(),
    };

    let mut refs = Vec::new();

    for (key, val) in map {
        let field_name = match key.as_text() {
            Some(n) => n,
            None => continue,
        };
        if let Some(field_spec) = type_def.fields.get(field_name) {
            collect_paths(val, field_name, field_spec, type_registry, &mut refs);
        }
    }

    refs
}

fn collect_paths(
    value: &ciborium::Value,
    field_name: &str,
    spec: &entity_types::FieldSpec,
    type_registry: &TypeRegistry,
    out: &mut Vec<(String, String)>,
) {
    // Direct path reference
    if let Some(ref type_ref) = spec.type_ref {
        if type_ref == "system/tree/path" {
            if let Some(path) = value.as_text() {
                out.push((path.to_string(), field_name.to_string()));
            }
            return;
        }
        // Recurse into referenced type
        if let Some(ref_def) = type_registry.get(type_ref) {
            if let Some(map) = value.as_map() {
                for (k, v) in map {
                    if let Some(sub_name) = k.as_text() {
                        if let Some(sub_spec) = ref_def.fields.get(sub_name) {
                            collect_paths(v, field_name, sub_spec, type_registry, out);
                        }
                    }
                }
            }
        }
    }

    // Array of elements
    if let Some(ref elem_spec) = spec.array_of {
        if let Some(arr) = value.as_array() {
            for item in arr {
                collect_paths(item, field_name, elem_spec, type_registry, out);
            }
        }
    }

    // Map of values
    if let Some(ref val_spec) = spec.map_of {
        if let Some(map) = value.as_map() {
            for (_, v) in map {
                collect_paths(v, field_name, val_spec, type_registry, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_hash::Hash;

    #[test]
    fn test_extract_hash_refs_simple() {
        let hash = Hash::compute("test", b"data");
        let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "target" => entity_ecf::Value::Bytes(hash.to_bytes().to_vec()),
            "name" => entity_ecf::text("foo")
        });
        let refs = extract_hash_refs(&data);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, hash);
        assert_eq!(refs[0].1, "target");
    }

    #[test]
    fn test_extract_hash_refs_nested() {
        let h1 = Hash::compute("test", b"one");
        let h2 = Hash::compute("test", b"two");
        let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "refs" => entity_ecf::Value::Array(vec![
                entity_ecf::Value::Bytes(h1.to_bytes().to_vec()),
                entity_ecf::Value::Bytes(h2.to_bytes().to_vec()),
            ])
        });
        let refs = extract_hash_refs(&data);
        assert_eq!(refs.len(), 2);
        assert!(refs.iter().any(|(h, _)| *h == h1));
        assert!(refs.iter().any(|(h, _)| *h == h2));
    }

    #[test]
    fn test_extract_hash_refs_no_hashes() {
        let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "name" => entity_ecf::text("hello")
        });
        let refs = extract_hash_refs(&data);
        assert!(refs.is_empty());
    }

    #[test]
    fn test_extract_hash_refs_ignores_non_hash_bytes() {
        let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "blob" => entity_ecf::Value::Bytes(vec![1, 2, 3, 4, 5])
        });
        let refs = extract_hash_refs(&data);
        assert!(refs.is_empty());
    }
}
