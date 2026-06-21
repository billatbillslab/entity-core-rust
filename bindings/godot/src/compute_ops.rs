//! Compute-op helpers — `ComputeValue` ↔ Godot Variant and result-shape
//! Dictionary mapping. Used by the `compute_*_async` `#[func]`s in
//! `peer_node.rs` via `raw_to_variant` in `peer_op_future.rs`.
//!
//! ## ComputeValue Variant shape (per the parity-sweep request §2.1)
//!
//! Emitted as a tagged Dictionary `{ "kind": <name>, "value": <typed> }`
//! rather than a raw Variant union, so GDScript callers can dispatch on
//! `result.kind` without ambiguity (Godot's `typeof()` collapses
//! Int/Uint, Bytes/PackedByteArray, etc.).
//!
//! Mapping:
//! | `ComputeValue` variant | `kind`     | `value`                                  |
//! |------------------------|------------|------------------------------------------|
//! | `Null`                 | `"null"`   | absent (only `kind` present)             |
//! | `Bool(b)`              | `"bool"`   | bool                                     |
//! | `Int(i)`               | `"int"`    | i64                                      |
//! | `Uint(u)`              | `"uint"`   | i64 (lossy for u > i64::MAX; warns)      |
//! | `Float(f)`             | `"float"`  | f64                                      |
//! | `Bytes(b)`             | `"bytes"`  | PackedByteArray                          |
//! | `Text(s)`              | `"text"`   | String                                   |
//! | `Hash(h)`              | `"hash"`   | PackedByteArray (33 bytes — algo + digest) |
//! | `Array(arr)`           | `"array"`  | Array[Dictionary] (recursive)            |
//! | `Map(m)`               | `"map"`    | Array of [k_dict, v_dict] pairs          |
//! | `Entity(e)`            | `"entity"` | EntityData                               |
//! | `Closure(e)`           | `"closure"`| EntityData                               |
//! | `Error(e)`             | `"error"`  | EntityData                               |
//!
//! Map values use an Array-of-pairs rather than a Dictionary because
//! ComputeValue keys can be non-string (Bytes, Int, Map). Godot
//! Dictionary keys must be hashable — wrapping a typed key as a
//! Dictionary makes it non-hashable. The pair-array preserves order
//! and any key type.

use godot::prelude::*;

use entity_sdk::compute::{ComputeEvalResult, ComputeInstallResult, ComputeValue, InstalledSubgraph};

use crate::entity_resource::EntityData;

/// Convert a [`ComputeValue`] into the tagged Dictionary documented at
/// the module level.
pub(crate) fn compute_value_to_variant(value: ComputeValue) -> Variant {
    let mut dict = Dictionary::new();
    match value {
        ComputeValue::Null => {
            dict.set("kind", "null");
        }
        ComputeValue::Bool(b) => {
            dict.set("kind", "bool");
            dict.set("value", b);
        }
        ComputeValue::Int(i) => {
            dict.set("kind", "int");
            dict.set("value", i);
        }
        ComputeValue::Uint(u) => {
            dict.set("kind", "uint");
            if u > i64::MAX as u64 {
                godot_warn!(
                    "ComputeValue::Uint({}) exceeds i64::MAX — clamped to i64",
                    u
                );
                dict.set("value", i64::MAX);
            } else {
                dict.set("value", u as i64);
            }
        }
        ComputeValue::Float(f) => {
            dict.set("kind", "float");
            dict.set("value", f);
        }
        ComputeValue::Bytes(b) => {
            let mut pba = PackedByteArray::new();
            pba.extend(b);
            dict.set("kind", "bytes");
            dict.set("value", pba);
        }
        ComputeValue::Text(s) => {
            dict.set("kind", "text");
            dict.set("value", GString::from(s.as_str()));
        }
        ComputeValue::Hash(h) => {
            let mut pba = PackedByteArray::new();
            pba.extend(h.to_bytes().to_vec());
            dict.set("kind", "hash");
            dict.set("value", pba);
        }
        ComputeValue::Array(arr) => {
            let mut godot_arr = VariantArray::new();
            for item in arr {
                godot_arr.push(&compute_value_to_variant(item));
            }
            dict.set("kind", "array");
            dict.set("value", godot_arr);
        }
        ComputeValue::Map(pairs) => {
            let mut godot_arr = VariantArray::new();
            for (k, v) in pairs {
                let mut pair = VariantArray::new();
                pair.push(&compute_value_to_variant(k));
                pair.push(&compute_value_to_variant(v));
                godot_arr.push(&pair.to_variant());
            }
            dict.set("kind", "map");
            dict.set("value", godot_arr);
        }
        ComputeValue::Entity(e) => {
            dict.set("kind", "entity");
            dict.set("value", EntityData::from_entity(&e));
        }
        ComputeValue::Closure(e) => {
            dict.set("kind", "closure");
            dict.set("value", EntityData::from_entity(&e));
        }
        ComputeValue::Error(e) => {
            dict.set("kind", "error");
            dict.set("value", EntityData::from_entity(&e));
        }
    }
    dict.to_variant()
}

/// Convert a `ComputeEvalResult` into the GDScript-facing Dictionary:
///   { value: <kind-dict>, result_entity: EntityData }
pub(crate) fn compute_eval_result_to_variant(r: ComputeEvalResult) -> Variant {
    let mut dict = Dictionary::new();
    let entity = EntityData::from_entity(&r.result_entity);
    dict.set("value", compute_value_to_variant(r.value));
    dict.set("result_entity", entity);
    dict.to_variant()
}

/// Convert a `ComputeInstallResult` into the GDScript-facing Dictionary:
///   { subgraph_path: String, result_path: String }
///
/// `impure_operations` is the raw walker CBOR map; we omit it from the
/// Variant surface for now (callers that need it can re-eval). Surface
/// when a panel actually needs it.
pub(crate) fn compute_install_result_to_variant(r: ComputeInstallResult) -> Variant {
    let mut dict = Dictionary::new();
    dict.set("subgraph_path", GString::from(r.subgraph_path.as_str()));
    dict.set("result_path", GString::from(r.result_path.as_str()));
    dict.to_variant()
}

/// Convert an `InstalledSubgraph` metadata entry into a Dictionary.
/// Used by `compute_list` / `compute_show` (sync L0 — no future).
pub(crate) fn installed_subgraph_to_dict(s: &InstalledSubgraph) -> Dictionary {
    let mut dict = Dictionary::new();
    dict.set("subgraph_path", GString::from(&s.subgraph_path));
    let mut hash_pba = PackedByteArray::new();
    hash_pba.extend(s.metadata_hash.to_bytes().to_vec());
    dict.set("metadata_hash", hash_pba);
    dict.set("root_expression_path", GString::from(&s.root_expression_path));
    dict.set("result_path", GString::from(&s.result_path));
    dict.set("status", GString::from(&s.status));
    let mut grant_pba = PackedByteArray::new();
    grant_pba.extend(s.installation_grant.to_bytes().to_vec());
    dict.set("installation_grant", grant_pba);
    let mut installer_pba = PackedByteArray::new();
    installer_pba.extend(s.installed_by.to_bytes().to_vec());
    dict.set("installed_by", installer_pba);
    dict
}
