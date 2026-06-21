//! `compare` (§7.2) and `compatible` (§7.3) operations on `system/type`.
//!
//! Both are read-only — they walk two type definitions resolved by tree
//! path and return analysis results inline. Resolution honors any
//! `system/tree/path` input (absolute, with leading `/{peer_id}/`, or
//! relative — relative paths are resolved under the local peer).

use std::sync::Arc;

use ciborium::Value;
use entity_ecf::{array, bool_val, text, to_ecf, ValueExt};
use entity_entity::Entity;
use entity_store::{ContentStore, LocationIndex};
use entity_types::{TYPE_COMPARE_RES, TYPE_COMPATIBILITY_REPORT};

/// Compare two type definitions structurally.
pub fn compare(
    type_a_path: &str,
    type_b_path: &str,
    local_peer_id: &str,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
) -> Result<Entity, String> {
    let def_a = resolve(local_peer_id, type_a_path, content_store, location_index)
        .ok_or_else(|| format!("type_a not resolved: {}", type_a_path))?;
    let def_b = resolve(local_peer_id, type_b_path, content_store, location_index)
        .ok_or_else(|| format!("type_b not resolved: {}", type_b_path))?;

    let fields_a = fields_of(&def_a);
    let fields_b = fields_of(&def_b);

    let mut shared = Vec::new();
    let mut only_a = Vec::new();
    let mut only_b = Vec::new();
    let mut incompatible = Vec::new();

    for (name, spec_a) in &fields_a {
        match fields_b.iter().find(|(n, _)| n == name) {
            Some((_, spec_b)) => {
                let a_type = type_ref(spec_a);
                let b_type = type_ref(spec_b);
                let type_match = a_type == b_type;
                let constraint_match =
                    to_ecf(&constraints(spec_a)) == to_ecf(&constraints(spec_b));
                if type_match {
                    shared.push((
                        name.clone(),
                        field_comparison(
                            type_match,
                            constraint_match,
                            is_optional(spec_a),
                            is_optional(spec_b),
                        ),
                    ));
                } else {
                    incompatible.push(field_incompatibility(name, &a_type, &b_type));
                }
            }
            None => only_a.push(name.clone()),
        }
    }
    for (name, _) in &fields_b {
        if !fields_a.iter().any(|(n, _)| n == name) {
            only_b.push(name.clone());
        }
    }

    let mut entries = vec![
        (text("type_a_path"), text(type_a_path)),
        (text("type_b_path"), text(type_b_path)),
        (
            text("shared"),
            Value::Map(shared.into_iter().map(|(k, v)| (text(&k), v)).collect()),
        ),
        (
            text("only_a"),
            array(only_a.into_iter().map(|s| text(&s)).collect()),
        ),
        (
            text("only_b"),
            array(only_b.into_iter().map(|s| text(&s)).collect()),
        ),
    ];
    if !incompatible.is_empty() {
        entries.push((text("incompatible"), array(incompatible)));
    }
    let data = to_ecf(&Value::Map(entries));
    Entity::new(TYPE_COMPARE_RES, data).map_err(|e| e.to_string())
}

/// Directional compatibility check.
pub fn compatible(
    type_a_path: &str,
    type_b_path: &str,
    direction: &str,
    local_peer_id: &str,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
) -> Result<Entity, String> {
    let def_a = resolve(local_peer_id, type_a_path, content_store, location_index)
        .ok_or_else(|| format!("type_a not resolved: {}", type_a_path))?;
    let def_b = resolve(local_peer_id, type_b_path, content_store, location_index)
        .ok_or_else(|| format!("type_b not resolved: {}", type_b_path))?;

    let fields_a = fields_of(&def_a);
    let fields_b = fields_of(&def_b);

    let mut shared_fields = Vec::new();
    let mut incompatible_fields: Vec<Value> = Vec::new();
    let mut missing_required_a = Vec::new();
    let mut missing_required_b = Vec::new();

    // Walk A's fields and classify against B.
    for (name, spec_a) in &fields_a {
        match fields_b.iter().find(|(n, _)| n == name) {
            Some((_, spec_b)) => {
                let a_type = type_ref(spec_a);
                let b_type = type_ref(spec_b);
                if a_type == b_type {
                    shared_fields.push(name.clone());
                } else {
                    incompatible_fields.push(field_incompatibility(name, &a_type, &b_type));
                }
            }
            None => {
                // Field is in A but not B. Forward (A → B): B doesn't
                // require it, fine. Backward (B → A): if A requires this
                // field, B is missing it.
                if !is_optional(spec_a) {
                    missing_required_b.push(name.clone());
                }
            }
        }
    }
    // Walk B's fields not in A — collect required-in-B-but-missing-in-A.
    // Forward (A → B) needs every B-required field present in A.
    for (name, spec_b) in &fields_b {
        if !fields_a.iter().any(|(n, _)| n == name) && !is_optional(spec_b) {
            missing_required_a.push(name.clone());
        }
    }

    // missing_required_X = X is missing fields someone else requires.
    // Forward (A satisfies B) requires A to have every B-required field
    // → forward_ok iff missing_required_a empty.
    // Backward (B satisfies A) requires B to have every A-required field
    // → backward_ok iff missing_required_b empty.
    let forward_ok = missing_required_a.is_empty() && incompatible_fields.is_empty();
    let backward_ok = missing_required_b.is_empty() && incompatible_fields.is_empty();
    let level = match (forward_ok, backward_ok) {
        (true, true) => "fully_compatible",
        (true, false) => "forward_only",
        (false, true) => "backward_only",
        (false, false) => {
            if !shared_fields.is_empty() && incompatible_fields.is_empty() {
                "partially_compatible"
            } else {
                "incompatible"
            }
        }
    };
    let direction_effective = if direction.is_empty() {
        "bidirectional"
    } else {
        direction
    };

    let mut entries = vec![
        (text("type_a_path"), text(type_a_path)),
        (text("type_b_path"), text(type_b_path)),
        (text("direction"), text(direction_effective)),
        (text("level"), text(level)),
        (
            text("shared_fields"),
            array(shared_fields.into_iter().map(|s| text(&s)).collect()),
        ),
    ];
    if !incompatible_fields.is_empty() {
        entries.push((text("incompatible_fields"), array(incompatible_fields)));
    }
    if !missing_required_a.is_empty() {
        entries.push((
            text("missing_required_a"),
            array(missing_required_a.into_iter().map(|s| text(&s)).collect()),
        ));
    }
    if !missing_required_b.is_empty() {
        entries.push((
            text("missing_required_b"),
            array(missing_required_b.into_iter().map(|s| text(&s)).collect()),
        ));
    }
    let data = to_ecf(&Value::Map(entries));
    Entity::new(TYPE_COMPATIBILITY_REPORT, data).map_err(|e| e.to_string())
}

fn resolve(
    local_peer_id: &str,
    path: &str,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
) -> Option<Value> {
    let qualified = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}/{}", local_peer_id, path)
    };
    let hash = location_index.get(&qualified)?;
    let entity = content_store.get(&hash)?;
    if entity.entity_type != "system/type" {
        return None;
    }
    ciborium::from_reader(entity.data.as_slice()).ok()
}

fn fields_of(def: &Value) -> Vec<(String, Value)> {
    def.get("fields")
        .and_then(|v| v.as_map().map(|m| m.to_vec()))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(k, v)| k.as_text().map(|s| (s.to_string(), v)))
        .collect()
}

fn type_ref(spec: &Value) -> String {
    spec.get("type_ref")
        .and_then(|v| v.as_text())
        .unwrap_or("")
        .to_string()
}

fn is_optional(spec: &Value) -> bool {
    spec.get("optional").and_then(|v| v.as_bool()).unwrap_or(false)
}

fn constraints(spec: &Value) -> Value {
    spec.get("constraints")
        .cloned()
        .unwrap_or(Value::Array(vec![]))
}

fn field_comparison(
    type_match: bool,
    constraint_match: bool,
    a_optional: bool,
    b_optional: bool,
) -> Value {
    Value::Map(vec![
        (text("type_match"), bool_val(type_match)),
        (text("constraint_match"), bool_val(constraint_match)),
        (text("a_optional"), bool_val(a_optional)),
        (text("b_optional"), bool_val(b_optional)),
    ])
}

fn field_incompatibility(field_name: &str, a_type: &str, b_type: &str) -> Value {
    Value::Map(vec![
        (text("field_name"), text(field_name)),
        (text("a_type"), text(a_type)),
        (text("b_type"), text(b_type)),
        (
            text("reason"),
            text("different type_ref between A and B"),
        ),
    ])
}
