//! Standard constraint handler at `system/type/constraint/*` (§5).
//!
//! Implements §5.4 dispatch on the 11 standard constraint kinds. Bound at
//! a single Handler with wildcard pattern; the operation is `validate`.
//!
//! Cross-impl gate: `one_of` / `not_one_of` use **ECF byte equality**
//! (§5.5 normative). Two impls MUST agree on whether a value matches a
//! `one_of` list. We satisfy this by ECF-encoding both sides via the
//! shared `entity_ecf::to_ecf` and comparing bytes.

use std::sync::Arc;

use async_trait::async_trait;
use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_OK,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::{
    TYPE_CONSTRAINT_FORMAT, TYPE_CONSTRAINT_MAX, TYPE_CONSTRAINT_MAX_COUNT,
    TYPE_CONSTRAINT_MAX_LENGTH, TYPE_CONSTRAINT_MIN, TYPE_CONSTRAINT_MIN_COUNT,
    TYPE_CONSTRAINT_MIN_LENGTH, TYPE_CONSTRAINT_NOT_ONE_OF, TYPE_CONSTRAINT_ONE_OF,
    TYPE_CONSTRAINT_PATTERN, TYPE_CONSTRAINT_TYPE_PATTERN, TYPE_CONSTRAINT_VALIDATE_RES,
};

use crate::format::validate_format;
use crate::glob::glob_match;

/// `system/type/constraint/*` handler.
///
/// The constraint handler optionally takes a content store + location
/// index so it can resolve hash / path references for the
/// `type_pattern` constraint (§4.6). Without them, `type_pattern` falls
/// back to the spec's "resolution failure → pass with warning" rule.
pub struct StandardConstraintHandler {
    qualified_pattern: String,
    content_store: Option<Arc<dyn ContentStore>>,
    location_index: Option<Arc<dyn LocationIndex>>,
    local_peer_id: String,
}

impl StandardConstraintHandler {
    pub fn new(local_peer_id: String) -> Self {
        // Bind at `system/type/constraint` (no `/*`). The V7 §6.6
        // longest-prefix resolver walks path segments backward; any
        // dispatch to `system/type/constraint/{kind}` finds this handler
        // when the lookup walks back to the parent prefix. The
        // wildcard suffix lives only in the published manifest's
        // `pattern` field (§5.1), not in the registry key.
        let qualified_pattern = format!("/{}/system/type/constraint", local_peer_id);
        Self {
            qualified_pattern,
            content_store: None,
            location_index: None,
            local_peer_id,
        }
    }

    /// Inject the content store + location index used by `type_pattern`
    /// to resolve hash / path references.
    pub fn with_tree_access(
        mut self,
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
    ) -> Self {
        self.content_store = Some(content_store);
        self.location_index = Some(location_index);
        self
    }

    fn evaluate(&self, req: &ValidateRequest) -> ValidateResult {
        match req.constraint_type.as_str() {
            TYPE_CONSTRAINT_MIN => eval_min(&req.value, &req.constraint_data),
            TYPE_CONSTRAINT_MAX => eval_max(&req.value, &req.constraint_data),
            TYPE_CONSTRAINT_MIN_LENGTH => {
                eval_min_length(&req.value, &req.constraint_data)
            }
            TYPE_CONSTRAINT_MAX_LENGTH => {
                eval_max_length(&req.value, &req.constraint_data)
            }
            TYPE_CONSTRAINT_MIN_COUNT => eval_min_count(&req.value, &req.constraint_data),
            TYPE_CONSTRAINT_MAX_COUNT => eval_max_count(&req.value, &req.constraint_data),
            TYPE_CONSTRAINT_PATTERN => eval_pattern(&req.value, &req.constraint_data),
            TYPE_CONSTRAINT_ONE_OF => eval_one_of(&req.value, &req.constraint_data, false),
            TYPE_CONSTRAINT_NOT_ONE_OF => {
                eval_one_of(&req.value, &req.constraint_data, true)
            }
            TYPE_CONSTRAINT_FORMAT => eval_format(&req.value, &req.constraint_data),
            TYPE_CONSTRAINT_TYPE_PATTERN => self.eval_type_pattern(&req.value, &req.constraint_data),
            other => ValidateResult::invalid(format!("unknown constraint type: {}", other)),
        }
    }

    fn eval_type_pattern(&self, value: &Value, data: &Value) -> ValidateResult {
        let pattern = match data.get("pattern").and_then(|v| v.as_text()) {
            Some(p) => p,
            None => return ValidateResult::invalid("type_pattern: missing pattern field"),
        };
        // The referenced entity may be addressed by hash (bstr) or by path
        // (text). Resolution may fail — spec §4.6 says: pass with warning
        // (we report valid=true; warnings are an open-type extension we
        // omit for v1.1 baseline).
        let resolved_type = if let Some(b) = value.as_bytes() {
            // Treat as hash.
            self.resolve_hash(b)
        } else if let Some(s) = value.as_text() {
            // Treat as tree path.
            self.resolve_path(s)
        } else {
            return ValidateResult::invalid("type_pattern: value not hash or path");
        };

        match resolved_type {
            // Resolution succeeded; check glob.
            Some(t) => {
                if glob_match(pattern, &t) {
                    ValidateResult::valid()
                } else {
                    ValidateResult::invalid(format!(
                        "type {} does not match pattern {}",
                        t, pattern
                    ))
                }
            }
            // Resolution failed — §4.6 pass-with-warning.
            None => ValidateResult::valid(),
        }
    }

    fn resolve_hash(&self, bytes: &[u8]) -> Option<String> {
        let store = self.content_store.as_ref()?;
        let hash = Hash::from_bytes(bytes).ok()?;
        let entity = store.get(&hash)?;
        Some(entity.entity_type)
    }

    fn resolve_path(&self, path: &str) -> Option<String> {
        let store = self.content_store.as_ref()?;
        let index = self.location_index.as_ref()?;
        let qualified = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}/{}", self.local_peer_id, path)
        };
        let hash = index.get(&qualified)?;
        let entity = store.get(&hash)?;
        Some(entity.entity_type)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for StandardConstraintHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        if ctx.operation != "validate" {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "unknown_operation",
                    &format!("system/type/constraint/* expects validate, got {}", ctx.operation),
                ),
            ));
        }
        let req = match ValidateRequest::from_entity(&ctx.params) {
            Ok(r) => r,
            Err(e) => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("bad_request", &e),
                ));
            }
        };
        let res = self.evaluate(&req);
        let res_entity = match res.to_entity() {
            Ok(e) => e,
            Err(e) => {
                return Ok(HandlerResult::error(
                    entity_handler::STATUS_INTERNAL_ERROR,
                    error_entity("encode_failure", &e),
                ));
            }
        };
        let _ = STATUS_OK;
        Ok(HandlerResult::ok(res_entity))
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "standard-constraints"
    }

    fn operations(&self) -> &[&str] {
        &["validate"]
    }
}

// ---------------------------------------------------------------------------
// Request / result wire shapes
// ---------------------------------------------------------------------------

/// Decoded `system/type/constraint/validate-request` (§5.2).
#[derive(Debug, Clone)]
pub struct ValidateRequest {
    pub value: Value,
    pub constraint_type: String,
    pub constraint_data: Value,
}

impl ValidateRequest {
    pub fn from_entity(entity: &Entity) -> Result<Self, String> {
        let value: Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| format!("decode: {}", e))?;
        let mut field_value: Option<Value> = None;
        let mut constraint_type: Option<String> = None;
        let mut constraint_data: Option<Value> = None;
        let entries = value
            .as_map()
            .ok_or_else(|| "params: expected map".to_string())?;
        for (k, v) in entries {
            match k.as_text() {
                Some("value") => field_value = Some(v.clone()),
                Some("constraint_type") => {
                    constraint_type = v.as_text().map(String::from);
                }
                Some("constraint_data") => constraint_data = Some(v.clone()),
                _ => {}
            }
        }
        Ok(Self {
            value: field_value.unwrap_or(Value::Null),
            constraint_type: constraint_type
                .ok_or_else(|| "missing constraint_type".to_string())?,
            constraint_data: constraint_data.unwrap_or(Value::Null),
        })
    }
}

/// Decoded `system/type/constraint/validate-result` (§5.3).
#[derive(Debug, Clone)]
pub struct ValidateResult {
    pub valid: bool,
    pub reason: Option<String>,
}

impl ValidateResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            reason: None,
        }
    }
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason: Some(reason.into()),
        }
    }
    pub fn to_entity(&self) -> Result<Entity, String> {
        let mut entries = vec![(
            entity_ecf::text("valid"),
            entity_ecf::bool_val(self.valid),
        )];
        if let Some(ref r) = self.reason {
            entries.push((entity_ecf::text("reason"), entity_ecf::text(r)));
        }
        let data = entity_ecf::to_ecf(&Value::Map(entries));
        Entity::new(TYPE_CONSTRAINT_VALIDATE_RES, data).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// §5.4 constraint evaluators
// ---------------------------------------------------------------------------

fn eval_min(value: &Value, data: &Value) -> ValidateResult {
    let min = match value_as_f64(data.get("min")) {
        Some(v) => v,
        None => return ValidateResult::invalid("min: missing or non-numeric min"),
    };
    let v = match value_as_f64(Some(value)) {
        Some(v) => v,
        None => return ValidateResult::invalid("min: not numeric"),
    };
    // §4.1: NaN comparisons return false.
    if v.is_nan() || min.is_nan() {
        return ValidateResult::invalid(format!("must be >= {}", min));
    }
    if v >= min {
        ValidateResult::valid()
    } else {
        ValidateResult::invalid(format!("must be >= {}", min))
    }
}

fn eval_max(value: &Value, data: &Value) -> ValidateResult {
    let max = match value_as_f64(data.get("max")) {
        Some(v) => v,
        None => return ValidateResult::invalid("max: missing or non-numeric max"),
    };
    let v = match value_as_f64(Some(value)) {
        Some(v) => v,
        None => return ValidateResult::invalid("max: not numeric"),
    };
    if v.is_nan() || max.is_nan() {
        return ValidateResult::invalid(format!("must be <= {}", max));
    }
    if v <= max {
        ValidateResult::valid()
    } else {
        ValidateResult::invalid(format!("must be <= {}", max))
    }
}

fn eval_min_length(value: &Value, data: &Value) -> ValidateResult {
    let min = match value_as_u64(data.get("min_length")) {
        Some(v) => v,
        None => return ValidateResult::invalid("min_length: missing or non-uint"),
    };
    let len = match measure_length(value) {
        Some(v) => v,
        None => return ValidateResult::invalid("min_length: not string or bytes"),
    };
    if len >= min {
        ValidateResult::valid()
    } else {
        ValidateResult::invalid(format!("length must be >= {}", min))
    }
}

fn eval_max_length(value: &Value, data: &Value) -> ValidateResult {
    let max = match value_as_u64(data.get("max_length")) {
        Some(v) => v,
        None => return ValidateResult::invalid("max_length: missing or non-uint"),
    };
    let len = match measure_length(value) {
        Some(v) => v,
        None => return ValidateResult::invalid("max_length: not string or bytes"),
    };
    if len <= max {
        ValidateResult::valid()
    } else {
        ValidateResult::invalid(format!("length must be <= {}", max))
    }
}

fn eval_min_count(value: &Value, data: &Value) -> ValidateResult {
    let min = match value_as_u64(data.get("min_count")) {
        Some(v) => v,
        None => return ValidateResult::invalid("min_count: missing or non-uint"),
    };
    let count = match collection_size(value) {
        Some(v) => v,
        None => return ValidateResult::invalid("min_count: not array or map"),
    };
    if count >= min {
        ValidateResult::valid()
    } else {
        ValidateResult::invalid(format!("count must be >= {}", min))
    }
}

fn eval_max_count(value: &Value, data: &Value) -> ValidateResult {
    let max = match value_as_u64(data.get("max_count")) {
        Some(v) => v,
        None => return ValidateResult::invalid("max_count: missing or non-uint"),
    };
    let count = match collection_size(value) {
        Some(v) => v,
        None => return ValidateResult::invalid("max_count: not array or map"),
    };
    if count <= max {
        ValidateResult::valid()
    } else {
        ValidateResult::invalid(format!("count must be <= {}", max))
    }
}

fn eval_pattern(value: &Value, data: &Value) -> ValidateResult {
    let pattern = match data.get("pattern").and_then(|v| v.as_text()) {
        Some(p) => p,
        None => return ValidateResult::invalid("pattern: missing pattern field"),
    };
    let s = match value.as_text() {
        Some(s) => s,
        None => return ValidateResult::invalid("pattern: not a string"),
    };
    // Full-match (`^...$`). The `regex` crate (Thompson NFA + lazy DFA) is
    // RE2-equivalent — linear time, no backreferences. Invalid pattern →
    // dispatch is invalid; caller sees fail-closed.
    let anchored = format!("^(?:{})$", pattern);
    let re = match regex::Regex::new(&anchored) {
        Ok(r) => r,
        Err(_) => {
            return ValidateResult::invalid(format!("invalid RE2 pattern: {}", pattern))
        }
    };
    if re.is_match(s) {
        ValidateResult::valid()
    } else {
        ValidateResult::invalid(format!("must match pattern: {}", pattern))
    }
}

fn eval_one_of(value: &Value, data: &Value, negate: bool) -> ValidateResult {
    let values = match data.get("values").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return ValidateResult::invalid("one_of: missing values field"),
    };
    // §4.4 / §5.5: ECF byte equality. This is the load-bearing cross-impl
    // gate — both sides MUST canonical-encode and compare bytes.
    let target = entity_ecf::to_ecf(value);
    let mut found = false;
    for candidate in values {
        if entity_ecf::to_ecf(candidate) == target {
            found = true;
            break;
        }
    }
    let valid = if negate { !found } else { found };
    if valid {
        ValidateResult::valid()
    } else if negate {
        ValidateResult::invalid("must not be one of the listed values")
    } else {
        ValidateResult::invalid("must be one of the listed values")
    }
}

fn eval_format(value: &Value, data: &Value) -> ValidateResult {
    let format = match data.get("format").and_then(|v| v.as_text()) {
        Some(f) => f,
        None => return ValidateResult::invalid("format: missing format field"),
    };
    let s = match value.as_text() {
        Some(s) => s,
        None => return ValidateResult::invalid("format: not a string"),
    };
    match validate_format(s, format) {
        Ok(true) => ValidateResult::valid(),
        Ok(false) => ValidateResult::invalid(format!("invalid {} format", format)),
        // §1.2 / §4.5: unknown format → fail closed. Caller's `system/type:
        // validate` translates this into `kind: "unknown_constraint"`.
        Err(name) => ValidateResult::invalid(format!("unknown format: {}", name)),
    }
}

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

fn value_as_f64(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Float(f) => Some(*f),
        Value::Integer(i) => {
            // ciborium::value::Integer → i128 conversion
            let n: i128 = (*i).into();
            Some(n as f64)
        }
        _ => None,
    }
}

fn value_as_u64(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Integer(i) => {
            u64::try_from(*i).ok()
        }
        _ => None,
    }
}

fn measure_length(value: &Value) -> Option<u64> {
    match value {
        Value::Text(s) => Some(s.chars().count() as u64),
        Value::Bytes(b) => Some(b.len() as u64),
        _ => None,
    }
}

fn collection_size(value: &Value) -> Option<u64> {
    match value {
        Value::Array(a) => Some(a.len() as u64),
        Value::Map(m) => Some(m.len() as u64),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

fn error_entity(error_type: &str, message: &str) -> Entity {
    let data = entity_ecf::to_ecf(&Value::Map(vec![
        (entity_ecf::text("type"), entity_ecf::text(error_type)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    Entity::new("system/protocol/error", data).expect("error entity")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Integer;

    fn make_request(
        constraint_type: &str,
        value: Value,
        constraint_data: Value,
    ) -> Entity {
        let data = entity_ecf::to_ecf(&Value::Map(vec![
            (entity_ecf::text("value"), value),
            (
                entity_ecf::text("constraint_type"),
                entity_ecf::text(constraint_type),
            ),
            (entity_ecf::text("constraint_data"), constraint_data),
        ]));
        Entity::new("system/type/constraint/validate-request", data).unwrap()
    }

    fn eval(handler: &StandardConstraintHandler, req: Entity) -> ValidateResult {
        let r = ValidateRequest::from_entity(&req).unwrap();
        handler.evaluate(&r)
    }

    fn handler() -> StandardConstraintHandler {
        StandardConstraintHandler::new("test-peer".to_string())
    }

    #[test]
    fn min_passes() {
        let req = make_request(
            TYPE_CONSTRAINT_MIN,
            Value::Integer(Integer::from(5u32)),
            Value::Map(vec![(entity_ecf::text("min"), entity_ecf::integer(3))]),
        );
        let r = eval(&handler(), req);
        assert!(r.valid);
    }

    #[test]
    fn min_fails_below() {
        let req = make_request(
            TYPE_CONSTRAINT_MIN,
            Value::Integer(Integer::from(1u32)),
            Value::Map(vec![(entity_ecf::text("min"), entity_ecf::integer(3))]),
        );
        let r = eval(&handler(), req);
        assert!(!r.valid);
    }

    #[test]
    fn min_rejects_non_numeric() {
        let req = make_request(
            TYPE_CONSTRAINT_MIN,
            entity_ecf::text("abc"),
            Value::Map(vec![(entity_ecf::text("min"), entity_ecf::integer(0))]),
        );
        let r = eval(&handler(), req);
        assert!(!r.valid);
        assert!(r.reason.unwrap().contains("not numeric"));
    }

    #[test]
    fn max_passes() {
        let req = make_request(
            TYPE_CONSTRAINT_MAX,
            entity_ecf::integer(10),
            Value::Map(vec![(entity_ecf::text("max"), entity_ecf::integer(20))]),
        );
        assert!(eval(&handler(), req).valid);
    }

    #[test]
    fn min_length_counts_codepoints() {
        // "héllo" = 5 codepoints, 6 bytes.
        let req = make_request(
            TYPE_CONSTRAINT_MIN_LENGTH,
            entity_ecf::text("héllo"),
            Value::Map(vec![(
                entity_ecf::text("min_length"),
                entity_ecf::integer(5),
            )]),
        );
        assert!(eval(&handler(), req).valid);
    }

    #[test]
    fn max_length_counts_codepoints() {
        let req = make_request(
            TYPE_CONSTRAINT_MAX_LENGTH,
            entity_ecf::text("héllo"),
            Value::Map(vec![(
                entity_ecf::text("max_length"),
                entity_ecf::integer(5),
            )]),
        );
        assert!(eval(&handler(), req).valid);
    }

    #[test]
    fn min_max_length_on_bytes() {
        // 4 bytes
        let req = make_request(
            TYPE_CONSTRAINT_MIN_LENGTH,
            Value::Bytes(vec![1, 2, 3, 4]),
            Value::Map(vec![(
                entity_ecf::text("min_length"),
                entity_ecf::integer(3),
            )]),
        );
        assert!(eval(&handler(), req).valid);
    }

    #[test]
    fn min_count_on_array() {
        let req = make_request(
            TYPE_CONSTRAINT_MIN_COUNT,
            entity_ecf::array(vec![entity_ecf::integer(1), entity_ecf::integer(2)]),
            Value::Map(vec![(
                entity_ecf::text("min_count"),
                entity_ecf::integer(2),
            )]),
        );
        assert!(eval(&handler(), req).valid);
    }

    #[test]
    fn pattern_full_match() {
        let req = make_request(
            TYPE_CONSTRAINT_PATTERN,
            entity_ecf::text("abc"),
            Value::Map(vec![(
                entity_ecf::text("pattern"),
                entity_ecf::text("[a-z]+"),
            )]),
        );
        assert!(eval(&handler(), req).valid);

        // Partial match should fail — full-match semantics.
        let req = make_request(
            TYPE_CONSTRAINT_PATTERN,
            entity_ecf::text("abc123"),
            Value::Map(vec![(
                entity_ecf::text("pattern"),
                entity_ecf::text("[a-z]+"),
            )]),
        );
        assert!(!eval(&handler(), req).valid);
    }

    #[test]
    fn one_of_ecf_byte_equality() {
        let values = entity_ecf::array(vec![
            entity_ecf::integer(1),
            entity_ecf::integer(2),
            entity_ecf::integer(3),
        ]);
        let req = make_request(
            TYPE_CONSTRAINT_ONE_OF,
            entity_ecf::integer(2),
            Value::Map(vec![(entity_ecf::text("values"), values)]),
        );
        assert!(eval(&handler(), req).valid);

        let values = entity_ecf::array(vec![entity_ecf::integer(1), entity_ecf::integer(3)]);
        let req = make_request(
            TYPE_CONSTRAINT_ONE_OF,
            entity_ecf::integer(2),
            Value::Map(vec![(entity_ecf::text("values"), values)]),
        );
        assert!(!eval(&handler(), req).valid);
    }

    #[test]
    fn not_one_of_negates() {
        let values = entity_ecf::array(vec![entity_ecf::integer(1), entity_ecf::integer(2)]);
        let req = make_request(
            TYPE_CONSTRAINT_NOT_ONE_OF,
            entity_ecf::integer(3),
            Value::Map(vec![(entity_ecf::text("values"), values)]),
        );
        assert!(eval(&handler(), req).valid);
    }

    #[test]
    fn format_known() {
        let req = make_request(
            TYPE_CONSTRAINT_FORMAT,
            entity_ecf::text("2026-05-28"),
            Value::Map(vec![(entity_ecf::text("format"), entity_ecf::text("date"))]),
        );
        assert!(eval(&handler(), req).valid);
    }

    #[test]
    fn format_unknown_fails_closed() {
        let req = make_request(
            TYPE_CONSTRAINT_FORMAT,
            entity_ecf::text("anything"),
            Value::Map(vec![(
                entity_ecf::text("format"),
                entity_ecf::text("email"),
            )]),
        );
        let r = eval(&handler(), req);
        assert!(!r.valid);
        assert!(r.reason.unwrap().starts_with("unknown format:"));
    }

    #[test]
    fn unknown_constraint_type_fails_closed() {
        let req = make_request(
            "app/custom/whatever",
            entity_ecf::integer(0),
            Value::Map(vec![]),
        );
        let r = eval(&handler(), req);
        assert!(!r.valid);
        assert!(r.reason.unwrap().starts_with("unknown constraint type:"));
    }

    #[test]
    fn pattern_rejects_invalid_regex() {
        // unterminated group — invalid RE2 syntax. Fail closed.
        let req = make_request(
            TYPE_CONSTRAINT_PATTERN,
            entity_ecf::text("anything"),
            Value::Map(vec![(entity_ecf::text("pattern"), entity_ecf::text("("))]),
        );
        let r = eval(&handler(), req);
        assert!(!r.valid);
    }

    #[test]
    fn one_of_ecf_canonical_floats() {
        // 1.0 (float) is encoded differently from 1 (int) in CBOR, so
        // ECF byte-equality should distinguish them.
        let values = entity_ecf::array(vec![Value::Float(1.0)]);
        let req = make_request(
            TYPE_CONSTRAINT_ONE_OF,
            entity_ecf::integer(1),
            Value::Map(vec![(entity_ecf::text("values"), values)]),
        );
        assert!(!eval(&handler(), req).valid);
    }
}
