//! Constraint narrowing verification (§6).
//!
//! When a type extends a parent, each child constraint must be narrower
//! than (or equal to) the parent's constraint of the same kind. §6.3
//! also forbids removing a parent constraint. Narrowing rules per §6.2:
//!
//! | constraint        | child narrower iff |
//! | ----------------- | ------------------ |
//! | min               | child.min >= parent.min |
//! | max               | child.max <= parent.max |
//! | min_length        | child >= parent |
//! | max_length        | child <= parent |
//! | min_count         | child >= parent |
//! | max_count         | child <= parent |
//! | pattern           | byte-equal only |
//! | one_of            | child.values ⊆ parent.values |
//! | not_one_of        | child.values ⊇ parent.values |
//! | format            | equal names only |
//! | type_pattern      | byte-equal only (interim — see SPEC-AMBIGUITIES) |
//!
//! `type_pattern` "more specific (longer prefix or exact match)" is not
//! algorithmically pinned by the spec. v1.1 deliberately keeps `pattern`
//! and `format` equal-only as the conservative interop default; we
//! treat `type_pattern` the same way for v1.1 — deployments wanting
//! richer narrowing layer it explicitly per the §6.2 framing for
//! `pattern` / `format`. Tracked in docs/SPEC-AMBIGUITIES.md if/when a
//! deployment surfaces a use case.

use std::collections::HashSet;
use std::sync::Arc;

use ciborium::Value;
use entity_ecf::ValueExt;
use entity_store::{ContentStore, LocationIndex};

use entity_types::{
    TYPE_CONSTRAINT_FORMAT, TYPE_CONSTRAINT_MAX, TYPE_CONSTRAINT_MAX_COUNT,
    TYPE_CONSTRAINT_MAX_LENGTH, TYPE_CONSTRAINT_MIN, TYPE_CONSTRAINT_MIN_COUNT,
    TYPE_CONSTRAINT_MIN_LENGTH, TYPE_CONSTRAINT_NOT_ONE_OF, TYPE_CONSTRAINT_ONE_OF,
    TYPE_CONSTRAINT_PATTERN, TYPE_CONSTRAINT_TYPE_PATTERN,
};

/// One narrowing violation, reported alongside structural / constraint
/// violations on the validate-result.
#[derive(Debug, Clone)]
pub struct NarrowingViolation {
    pub field: String,
    pub constraint: String,
    pub reason: String,
}

/// Resolve a type definition by name via Strategy 1 path-convention
/// lookup, then verify narrowing for any child→parent→… chain via
/// `extends`. Returns the collected narrowing violations.
///
/// Cycle detection (§1.5 invariant 3) is graph-level: a name already
/// visited fails closed with a single synthetic "cycle" violation.
pub fn verify_narrowing(
    child_def: &Value,
    local_peer_id: &str,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
) -> Vec<NarrowingViolation> {
    let mut violations = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let child_name = child_def
        .get("name")
        .and_then(|v| v.as_text())
        .unwrap_or_default()
        .to_string();
    visited.insert(child_name);

    let mut current = child_def.clone();
    loop {
        let parent_name = match current
            .get("extends")
            .and_then(|v| v.as_text())
            .filter(|s| !s.is_empty())
        {
            Some(s) => s.to_string(),
            None => break,
        };
        if !visited.insert(parent_name.clone()) {
            violations.push(NarrowingViolation {
                field: String::new(),
                constraint: String::new(),
                reason: format!("extends cycle detected at {}", parent_name),
            });
            break;
        }
        let parent_def = match resolve_type(
            local_peer_id,
            &parent_name,
            content_store,
            location_index,
        ) {
            Some(v) => v,
            None => {
                violations.push(NarrowingViolation {
                    field: String::new(),
                    constraint: String::new(),
                    reason: format!("parent type not resolved: {}", parent_name),
                });
                break;
            }
        };
        // Compare constraints for each field present on parent.
        verify_step(&current, &parent_def, &mut violations);
        current = parent_def;
    }
    violations
}

fn resolve_type(
    local_peer_id: &str,
    name: &str,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
) -> Option<Value> {
    let path = format!("/{}/system/type/{}", local_peer_id, name);
    let hash = location_index.get(&path)?;
    let entity = content_store.get(&hash)?;
    if entity.entity_type != "system/type" {
        return None;
    }
    ciborium::from_reader(entity.data.as_slice()).ok()
}

fn verify_step(child: &Value, parent: &Value, out: &mut Vec<NarrowingViolation>) {
    let parent_fields = match parent.get("fields").and_then(|v| v.as_map()) {
        Some(m) => m.to_vec(),
        None => return,
    };
    let child_fields = child
        .get("fields")
        .and_then(|v| v.as_map().map(|m| m.to_vec()))
        .unwrap_or_default();

    for (k, parent_spec) in &parent_fields {
        let field_name = match k.as_text() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let parent_constraints = constraints_of(parent_spec);
        if parent_constraints.is_empty() {
            continue;
        }
        let child_spec = child_fields
            .iter()
            .find(|(k2, _)| k2.as_text() == Some(field_name.as_str()))
            .map(|(_, v)| v.clone());
        let child_constraints = child_spec
            .as_ref()
            .map(constraints_of)
            .unwrap_or_default();

        for parent_c in &parent_constraints {
            let kind = constraint_type_of(parent_c);
            // §6.3 — child MUST keep every parent constraint kind.
            let matching = child_constraints
                .iter()
                .find(|c| constraint_type_of(c) == kind);
            let matching = match matching {
                Some(m) => m,
                None => {
                    out.push(NarrowingViolation {
                        field: field_name.clone(),
                        constraint: kind.to_string(),
                        reason: "child removed parent constraint".to_string(),
                    });
                    continue;
                }
            };
            if let Err(msg) = check_narrower(&kind, matching, parent_c) {
                out.push(NarrowingViolation {
                    field: field_name.clone(),
                    constraint: kind.to_string(),
                    reason: msg,
                });
            }
        }
    }
}

fn constraints_of(field_spec: &Value) -> Vec<Value> {
    field_spec
        .get("constraints")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

fn constraint_type_of(c: &Value) -> String {
    c.get("type")
        .and_then(|v| v.as_text())
        .unwrap_or_default()
        .to_string()
}

fn constraint_data_of(c: &Value) -> Value {
    c.get("data").cloned().unwrap_or(Value::Null)
}

/// Per-kind narrowing check. Returns Err(reason) when child WIDENS or
/// the constraint is "incomparable" by the spec's equal-only rule.
fn check_narrower(kind: &str, child: &Value, parent: &Value) -> Result<(), String> {
    let cd = constraint_data_of(child);
    let pd = constraint_data_of(parent);
    match kind {
        TYPE_CONSTRAINT_MIN => narrow_ge(&cd, &pd, "min"),
        TYPE_CONSTRAINT_MAX => narrow_le(&cd, &pd, "max"),
        TYPE_CONSTRAINT_MIN_LENGTH => narrow_ge_uint(&cd, &pd, "min_length"),
        TYPE_CONSTRAINT_MAX_LENGTH => narrow_le_uint(&cd, &pd, "max_length"),
        TYPE_CONSTRAINT_MIN_COUNT => narrow_ge_uint(&cd, &pd, "min_count"),
        TYPE_CONSTRAINT_MAX_COUNT => narrow_le_uint(&cd, &pd, "max_count"),
        TYPE_CONSTRAINT_PATTERN => {
            // §6.2 v1.1 — equal-only.
            let cp = cd.get("pattern").and_then(|v| v.as_text()).unwrap_or("");
            let pp = pd.get("pattern").and_then(|v| v.as_text()).unwrap_or("");
            if cp == pp {
                Ok(())
            } else {
                Err("non-equal patterns are incomparable".to_string())
            }
        }
        TYPE_CONSTRAINT_FORMAT => {
            let cf = cd.get("format").and_then(|v| v.as_text()).unwrap_or("");
            let pf = pd.get("format").and_then(|v| v.as_text()).unwrap_or("");
            if cf == pf {
                Ok(())
            } else {
                Err("non-equal formats are incomparable".to_string())
            }
        }
        TYPE_CONSTRAINT_TYPE_PATTERN => {
            // First-pass: equal-only. See module doc for spec-ambiguity note.
            let cp = cd.get("pattern").and_then(|v| v.as_text()).unwrap_or("");
            let pp = pd.get("pattern").and_then(|v| v.as_text()).unwrap_or("");
            if cp == pp {
                Ok(())
            } else {
                Err("non-equal type_patterns are incomparable (v1.1 baseline)".to_string())
            }
        }
        TYPE_CONSTRAINT_ONE_OF => {
            // child.values ⊆ parent.values (ECF byte equality per element).
            let cv = cd
                .get("values")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            let pv = pd
                .get("values")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            let pv_bytes: Vec<Vec<u8>> = pv.iter().map(entity_ecf::to_ecf).collect();
            for v in &cv {
                let b = entity_ecf::to_ecf(v);
                if !pv_bytes.iter().any(|p| p == &b) {
                    return Err("child one_of contains value not in parent".to_string());
                }
            }
            Ok(())
        }
        TYPE_CONSTRAINT_NOT_ONE_OF => {
            // child.values ⊇ parent.values.
            let cv = cd
                .get("values")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            let pv = pd
                .get("values")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            let cv_bytes: Vec<Vec<u8>> = cv.iter().map(entity_ecf::to_ecf).collect();
            for v in &pv {
                let b = entity_ecf::to_ecf(v);
                if !cv_bytes.iter().any(|c| c == &b) {
                    return Err(
                        "child not_one_of missing value present in parent".to_string()
                    );
                }
            }
            Ok(())
        }
        _ => Ok(()), // Unknown constraint kind — let validate flag it.
    }
}

fn narrow_ge(child: &Value, parent: &Value, key: &str) -> Result<(), String> {
    let c = as_f64(child.get(key)).ok_or_else(|| format!("missing {} on child", key))?;
    let p = as_f64(parent.get(key)).ok_or_else(|| format!("missing {} on parent", key))?;
    if c >= p {
        Ok(())
    } else {
        Err(format!("child {} ({}) widens parent ({})", key, c, p))
    }
}

fn narrow_le(child: &Value, parent: &Value, key: &str) -> Result<(), String> {
    let c = as_f64(child.get(key)).ok_or_else(|| format!("missing {} on child", key))?;
    let p = as_f64(parent.get(key)).ok_or_else(|| format!("missing {} on parent", key))?;
    if c <= p {
        Ok(())
    } else {
        Err(format!("child {} ({}) widens parent ({})", key, c, p))
    }
}

fn narrow_ge_uint(child: &Value, parent: &Value, key: &str) -> Result<(), String> {
    let c = as_u64(child.get(key)).ok_or_else(|| format!("missing {} on child", key))?;
    let p = as_u64(parent.get(key)).ok_or_else(|| format!("missing {} on parent", key))?;
    if c >= p {
        Ok(())
    } else {
        Err(format!("child {} ({}) widens parent ({})", key, c, p))
    }
}

fn narrow_le_uint(child: &Value, parent: &Value, key: &str) -> Result<(), String> {
    let c = as_u64(child.get(key)).ok_or_else(|| format!("missing {} on child", key))?;
    let p = as_u64(parent.get(key)).ok_or_else(|| format!("missing {} on parent", key))?;
    if c <= p {
        Ok(())
    } else {
        Err(format!("child {} ({}) widens parent ({})", key, c, p))
    }
}

fn as_f64(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Float(f) => Some(*f),
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            Some(n as f64)
        }
        _ => None,
    }
}

fn as_u64(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_ecf::{cbor_map, integer, text};

    fn ct(kind: &str, data: Value) -> Value {
        cbor_map! {
            "type" => text(kind),
            "data" => data
        }
    }

    #[test]
    fn min_narrows() {
        let parent = ct(TYPE_CONSTRAINT_MIN, cbor_map! { "min" => integer(0) });
        let child = ct(TYPE_CONSTRAINT_MIN, cbor_map! { "min" => integer(5) });
        assert!(check_narrower(TYPE_CONSTRAINT_MIN, &child, &parent).is_ok());
    }

    #[test]
    fn min_widens_rejected() {
        let parent = ct(TYPE_CONSTRAINT_MIN, cbor_map! { "min" => integer(5) });
        let child = ct(TYPE_CONSTRAINT_MIN, cbor_map! { "min" => integer(0) });
        assert!(check_narrower(TYPE_CONSTRAINT_MIN, &child, &parent).is_err());
    }

    #[test]
    fn max_narrows() {
        let parent = ct(TYPE_CONSTRAINT_MAX, cbor_map! { "max" => integer(100) });
        let child = ct(TYPE_CONSTRAINT_MAX, cbor_map! { "max" => integer(10) });
        assert!(check_narrower(TYPE_CONSTRAINT_MAX, &child, &parent).is_ok());
    }

    #[test]
    fn pattern_equal_only() {
        let parent = ct(
            TYPE_CONSTRAINT_PATTERN,
            cbor_map! { "pattern" => text("[a-z]+") },
        );
        let child_equal = ct(
            TYPE_CONSTRAINT_PATTERN,
            cbor_map! { "pattern" => text("[a-z]+") },
        );
        let child_different = ct(
            TYPE_CONSTRAINT_PATTERN,
            cbor_map! { "pattern" => text("[a-z]{3,5}") },
        );
        assert!(check_narrower(TYPE_CONSTRAINT_PATTERN, &child_equal, &parent).is_ok());
        // Even though [a-z]{3,5} is intuitively narrower than [a-z]+, the
        // spec rule is equal-only — non-equal patterns are incomparable.
        assert!(check_narrower(TYPE_CONSTRAINT_PATTERN, &child_different, &parent).is_err());
    }

    #[test]
    fn format_equal_only() {
        let parent = ct(
            TYPE_CONSTRAINT_FORMAT,
            cbor_map! { "format" => text("date-time") },
        );
        let child_date = ct(
            TYPE_CONSTRAINT_FORMAT,
            cbor_map! { "format" => text("date") },
        );
        // Even if `date` is intuitively a sub-format of `date-time`, the
        // spec says incomparable by default.
        assert!(check_narrower(TYPE_CONSTRAINT_FORMAT, &child_date, &parent).is_err());
    }

    #[test]
    fn one_of_subset() {
        let parent = ct(
            TYPE_CONSTRAINT_ONE_OF,
            cbor_map! {
                "values" => entity_ecf::array(vec![integer(1), integer(2), integer(3)])
            },
        );
        let child_subset = ct(
            TYPE_CONSTRAINT_ONE_OF,
            cbor_map! {
                "values" => entity_ecf::array(vec![integer(1), integer(2)])
            },
        );
        let child_superset = ct(
            TYPE_CONSTRAINT_ONE_OF,
            cbor_map! {
                "values" => entity_ecf::array(vec![integer(1), integer(2), integer(3), integer(4)])
            },
        );
        assert!(check_narrower(TYPE_CONSTRAINT_ONE_OF, &child_subset, &parent).is_ok());
        assert!(check_narrower(TYPE_CONSTRAINT_ONE_OF, &child_superset, &parent).is_err());
    }

    #[test]
    fn not_one_of_superset() {
        let parent = ct(
            TYPE_CONSTRAINT_NOT_ONE_OF,
            cbor_map! {
                "values" => entity_ecf::array(vec![integer(1), integer(2)])
            },
        );
        // Child denies more — superset of parent's deny-list.
        let child_super = ct(
            TYPE_CONSTRAINT_NOT_ONE_OF,
            cbor_map! {
                "values" => entity_ecf::array(vec![integer(1), integer(2), integer(3)])
            },
        );
        let child_sub = ct(
            TYPE_CONSTRAINT_NOT_ONE_OF,
            cbor_map! {
                "values" => entity_ecf::array(vec![integer(1)])
            },
        );
        assert!(check_narrower(TYPE_CONSTRAINT_NOT_ONE_OF, &child_super, &parent).is_ok());
        assert!(check_narrower(TYPE_CONSTRAINT_NOT_ONE_OF, &child_sub, &parent).is_err());
    }
}
