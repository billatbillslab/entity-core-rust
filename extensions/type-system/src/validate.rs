//! `system/type:validate` handler — two-phase validation (§2.3).
//!
//! Phase 1: structural validation (entity type matches, required fields
//! present). Phase 2: constraint dispatch — for each field-spec carrying
//! `constraints`, dispatch each constraint to the appropriate handler via
//! `ctx.execute_fn`. Resolution uses Strategy 1 (path-convention lookup)
//! per v1.1 §1.5.
//!
//! Unknown-constraint classification (§1.2 / §8.5):
//! - Dispatch returns valid=false with `reason` starting with "unknown
//!   constraint type:" or "unknown format:" → kind="unknown_constraint".
//! - Dispatch fails entirely (no handler matched, internal error) →
//!   kind="unknown_constraint" with reason capturing the dispatch failure.
//! - Otherwise valid=false → kind="constraint".

use std::sync::Arc;

use async_trait::async_trait;
use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_handler::{
    ExecuteOptions, Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST,
    STATUS_OK,
};
use entity_store::LocationIndex;
use entity_types::{TYPE_VALIDATE_RES, TYPE_VIOLATION};

use crate::{compare, narrowing};

/// `system/type` handler — validate (R-T3 of EXTENSION-TYPE v1.1).
pub struct TypeHandler {
    qualified_pattern: String,
    local_peer_id: String,
    content_store: Arc<dyn entity_store::ContentStore>,
    location_index: Arc<dyn LocationIndex>,
}

impl TypeHandler {
    pub fn new(
        local_peer_id: String,
        content_store: Arc<dyn entity_store::ContentStore>,
        location_index: Arc<dyn LocationIndex>,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/type", local_peer_id);
        Self {
            qualified_pattern,
            local_peer_id,
            content_store,
            location_index,
        }
    }

    /// Look up a type definition by name via Strategy 1
    /// (`system/type/{name}` path lookup). Returns the decoded data
    /// (ciborium Value of the `system/type` entity's data map) and the
    /// canonical name.
    fn resolve_type(&self, name: &str) -> Option<Value> {
        let path = format!("/{}/system/type/{}", self.local_peer_id, name);
        let hash = self.location_index.get(&path)?;
        let entity = self.content_store.get(&hash)?;
        if entity.entity_type != "system/type" {
            return None;
        }
        ciborium::from_reader(entity.data.as_slice()).ok()
    }

    async fn handle_validate(&self, ctx: &HandlerContext) -> HandlerResult {
        // Decode the validate-request.
        let params_value: Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("bad_request", &format!("decode params: {}", e)),
                );
            }
        };
        let (entity_value, type_path_override) = match parse_validate_request(&params_value) {
            Ok(t) => t,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("bad_request", &e),
                );
            }
        };

        // Extract the entity's type + data from the inline core/entity map.
        let entity_type = match entity_value.get("type").and_then(|v| v.as_text()) {
            Some(s) => s.to_string(),
            None => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("bad_request", "entity.type missing"),
                );
            }
        };
        let entity_data = entity_value
            .get("data")
            .cloned()
            .unwrap_or(Value::Map(vec![]));

        // Resolve type definition by Strategy 1.
        let type_name = type_path_override.unwrap_or(entity_type.clone());
        let type_def_data = match self.resolve_type(&type_name) {
            Some(v) => v,
            None => {
                // Type not found → report as structural violation.
                let violations = vec![Violation {
                    field: String::new(),
                    kind: "structural".to_string(),
                    constraint: None,
                    reason: format!("type not resolved: {}", type_name),
                }];
                let result = ValidateResult {
                    valid: false,
                    violations,
                    unevaluated_fields: Vec::new(),
                };
                return HandlerResult::ok(result.to_entity());
            }
        };

        let mut violations: Vec<Violation> = Vec::new();
        let mut unevaluated_fields: Vec<String> = Vec::new();

        // Phase 1: structural validation (minimal — type match + required
        // field presence). Deep CBOR-type coercion checking belongs to
        // ENTITY-NATIVE-TYPE-SYSTEM core (not this extension); the Rust
        // kernel has no general structural validator yet — logged in
        // docs/SPEC-AMBIGUITIES.md as an impl gap. The validator here
        // covers what's locally derivable from a `system/type` entity.
        let fields_map = type_def_data
            .get("fields")
            .and_then(|v| v.as_map().map(|m| m.to_vec()))
            .unwrap_or_default();

        // The entity's data should be a map for fielded types.
        let entity_fields = entity_data
            .as_map()
            .map(|m| m.to_vec())
            .unwrap_or_default();
        let present_keys: Vec<String> = entity_fields
            .iter()
            .filter_map(|(k, _)| k.as_text().map(String::from))
            .collect();

        for (k, spec_v) in &fields_map {
            let field_name = match k.as_text() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let optional = spec_v
                .get("optional")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let value = entity_fields
                .iter()
                .find(|(k2, _)| k2.as_text() == Some(field_name.as_str()))
                .map(|(_, v)| v.clone());

            if value.is_none() {
                if !optional {
                    violations.push(Violation {
                        field: field_name.clone(),
                        kind: "structural".to_string(),
                        constraint: None,
                        reason: "required field missing".to_string(),
                    });
                }
                // Absent optional field: skip constraints (§2.3).
                continue;
            }
            let value = value.unwrap();

            // Phase 2: constraint dispatch for this field.
            let constraints = spec_v
                .get("constraints")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            for constraint in &constraints {
                let (c_type, c_data) = match decode_constraint(constraint) {
                    Some(t) => t,
                    None => continue,
                };
                let v = self
                    .dispatch_constraint(ctx, &value, &c_type, &c_data)
                    .await;
                match v {
                    DispatchOutcome::Valid => {}
                    DispatchOutcome::Invalid { reason } => {
                        let kind = classify_reason(&reason);
                        violations.push(Violation {
                            field: field_name.clone(),
                            kind: kind.to_string(),
                            constraint: Some(c_type.clone()),
                            reason,
                        });
                    }
                    DispatchOutcome::DispatchFailed { reason } => {
                        violations.push(Violation {
                            field: field_name.clone(),
                            kind: "unknown_constraint".to_string(),
                            constraint: Some(c_type.clone()),
                            reason: format!("constraint_dispatch_failed: {}", reason),
                        });
                    }
                }
            }
        }

        // §6.4 narrowing verification — when the entity being validated
        // IS a `system/type` definition with `extends`, walk the parent
        // chain and verify per-field per-constraint narrowing.
        if entity_type == "system/type" {
            let narrowing_violations = narrowing::verify_narrowing(
                &entity_data,
                &self.local_peer_id,
                &self.content_store,
                &self.location_index,
            );
            for nv in narrowing_violations {
                violations.push(Violation {
                    field: nv.field,
                    kind: "structural".to_string(),
                    constraint: if nv.constraint.is_empty() {
                        None
                    } else {
                        Some(nv.constraint)
                    },
                    reason: format!("narrowing violation: {}", nv.reason),
                });
            }
        }

        // Detect open-type extension fields the validator didn't interpret.
        // §8.4: at the type-definition level (e.g., unknown extension
        // fields on a system/type entity). For v1.1 baseline, we only
        // report field-spec-level extensions we don't recognize; this is
        // a forward-looking placeholder. Currently empty — known
        // extension fields (constraints) are evaluated above.
        let _ = &mut unevaluated_fields;
        let _ = &present_keys;

        let result = ValidateResult {
            valid: violations.is_empty(),
            violations,
            unevaluated_fields,
        };
        HandlerResult::ok(result.to_entity())
    }

    async fn dispatch_constraint(
        &self,
        ctx: &HandlerContext,
        value: &Value,
        constraint_type: &str,
        constraint_data: &Value,
    ) -> DispatchOutcome {
        let execute_fn = match ctx.execute_fn.as_ref() {
            Some(f) => f.clone(),
            None => {
                return DispatchOutcome::DispatchFailed {
                    reason: "no execute_fn".to_string(),
                };
            }
        };
        let req_data = entity_ecf::to_ecf(&Value::Map(vec![
            (entity_ecf::text("value"), value.clone()),
            (
                entity_ecf::text("constraint_type"),
                entity_ecf::text(constraint_type),
            ),
            (
                entity_ecf::text("constraint_data"),
                constraint_data.clone(),
            ),
        ]));
        let req = match Entity::new("system/type/constraint/validate-request", req_data) {
            Ok(e) => e,
            Err(e) => {
                return DispatchOutcome::DispatchFailed {
                    reason: format!("build request: {}", e),
                };
            }
        };
        let opts = ExecuteOptions::default();
        match execute_fn(
            constraint_type.to_string(),
            "validate".to_string(),
            req,
            opts,
        )
        .await
        {
            Ok(res) => {
                // Non-OK status from the dispatched handler (4xx/5xx)
                // means the handler couldn't evaluate the constraint —
                // classify as unknown_constraint per §1.2 fail-closed.
                if res.status != STATUS_OK {
                    DispatchOutcome::DispatchFailed {
                        reason: format!("handler status {}", res.status),
                    }
                } else {
                    parse_dispatch_result(&res.result)
                }
            }
            Err(e) => DispatchOutcome::DispatchFailed {
                reason: format!("{}", e),
            },
        }
    }

    fn handle_compare(&self, ctx: &HandlerContext) -> HandlerResult {
        let value: Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("bad_request", &format!("decode: {}", e)),
                );
            }
        };
        let type_a = value.get("type_a").and_then(|v| v.as_text()).unwrap_or("");
        let type_b = value.get("type_b").and_then(|v| v.as_text()).unwrap_or("");
        if type_a.is_empty() || type_b.is_empty() {
            return HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity("bad_request", "type_a and type_b required"),
            );
        }
        match compare::compare(
            type_a,
            type_b,
            &self.local_peer_id,
            &self.content_store,
            &self.location_index,
        ) {
            Ok(e) => HandlerResult::ok(e),
            Err(msg) => HandlerResult::error(
                entity_handler::STATUS_NOT_FOUND,
                error_entity("not_found", &msg),
            ),
        }
    }

    fn handle_compatible(&self, ctx: &HandlerContext) -> HandlerResult {
        let value: Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("bad_request", &format!("decode: {}", e)),
                );
            }
        };
        let type_a = value.get("type_a").and_then(|v| v.as_text()).unwrap_or("");
        let type_b = value.get("type_b").and_then(|v| v.as_text()).unwrap_or("");
        let direction = value
            .get("direction")
            .and_then(|v| v.as_text())
            .unwrap_or("bidirectional");
        if type_a.is_empty() || type_b.is_empty() {
            return HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity("bad_request", "type_a and type_b required"),
            );
        }
        match compare::compatible(
            type_a,
            type_b,
            direction,
            &self.local_peer_id,
            &self.content_store,
            &self.location_index,
        ) {
            Ok(e) => HandlerResult::ok(e),
            Err(msg) => HandlerResult::error(
                entity_handler::STATUS_NOT_FOUND,
                error_entity("not_found", &msg),
            ),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for TypeHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "validate" => Ok(self.handle_validate(ctx).await),
            "compare" => Ok(self.handle_compare(ctx)),
            "compatible" => Ok(self.handle_compatible(ctx)),
            other => Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "unknown_operation",
                    &format!("system/type does not support {}", other),
                ),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "types"
    }

    fn operations(&self) -> &[&str] {
        &["validate", "compare", "compatible"]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Violation {
    pub field: String,
    pub kind: String,
    pub constraint: Option<String>,
    pub reason: String,
}

impl Violation {
    pub fn to_entity(&self) -> Entity {
        let mut entries = vec![
            (entity_ecf::text("field"), entity_ecf::text(&self.field)),
            (entity_ecf::text("kind"), entity_ecf::text(&self.kind)),
            (entity_ecf::text("reason"), entity_ecf::text(&self.reason)),
        ];
        if let Some(ref c) = self.constraint {
            entries.push((entity_ecf::text("constraint"), entity_ecf::text(c)));
        }
        let data = entity_ecf::to_ecf(&Value::Map(entries));
        Entity::new(TYPE_VIOLATION, data).expect("violation entity")
    }
}

#[derive(Debug, Clone)]
pub struct ValidateResult {
    pub valid: bool,
    pub violations: Vec<Violation>,
    pub unevaluated_fields: Vec<String>,
}

impl ValidateResult {
    pub fn to_entity(&self) -> Entity {
        let mut entries = vec![(
            entity_ecf::text("valid"),
            entity_ecf::bool_val(self.valid),
        )];
        if !self.violations.is_empty() {
            let arr: Vec<Value> = self
                .violations
                .iter()
                .map(|v| {
                    let e = v.to_entity();
                    let inner: Value = ciborium::from_reader(e.data.as_slice())
                        .unwrap_or(Value::Map(vec![]));
                    inner
                })
                .collect();
            entries.push((entity_ecf::text("violations"), entity_ecf::array(arr)));
        }
        if !self.unevaluated_fields.is_empty() {
            let arr: Vec<Value> = self
                .unevaluated_fields
                .iter()
                .map(|s| entity_ecf::text(s.as_str()))
                .collect();
            entries.push((entity_ecf::text("unevaluated_fields"), entity_ecf::array(arr)));
        }
        let data = entity_ecf::to_ecf(&Value::Map(entries));
        Entity::new(TYPE_VALIDATE_RES, data).expect("validate-result entity")
    }
}

fn parse_validate_request(value: &Value) -> Result<(Value, Option<String>), String> {
    let map = value
        .as_map()
        .ok_or_else(|| "validate-request must be a map".to_string())?;
    let mut entity_v: Option<Value> = None;
    let mut type_path: Option<String> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("entity") => entity_v = Some(v.clone()),
            Some("type_path") => type_path = v.as_text().map(String::from),
            _ => {}
        }
    }
    Ok((
        entity_v.ok_or_else(|| "missing entity".to_string())?,
        type_path,
    ))
}

/// Decode a constraint entry (`{type, data, content_hash}` shape) into
/// (constraint_type, inline constraint data).
fn decode_constraint(value: &Value) -> Option<(String, Value)> {
    let map = value.as_map()?;
    let mut c_type = None;
    let mut c_data = None;
    for (k, v) in map {
        match k.as_text() {
            Some("type") => c_type = v.as_text().map(String::from),
            Some("data") => c_data = Some(v.clone()),
            _ => {}
        }
    }
    Some((c_type?, c_data.unwrap_or(Value::Null)))
}

#[derive(Debug)]
enum DispatchOutcome {
    Valid,
    Invalid { reason: String },
    DispatchFailed { reason: String },
}

fn parse_dispatch_result(entity: &Entity) -> DispatchOutcome {
    let value: Value = match ciborium::from_reader(entity.data.as_slice()) {
        Ok(v) => v,
        Err(e) => {
            return DispatchOutcome::DispatchFailed {
                reason: format!("decode: {}", e),
            };
        }
    };
    let valid = value
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let reason = value
        .get("reason")
        .and_then(|v| v.as_text())
        .map(String::from)
        .unwrap_or_default();
    if valid {
        DispatchOutcome::Valid
    } else {
        DispatchOutcome::Invalid { reason }
    }
}

fn classify_reason(reason: &str) -> &'static str {
    if reason.starts_with("unknown constraint type:") || reason.starts_with("unknown format:") {
        "unknown_constraint"
    } else {
        "constraint"
    }
}

fn error_entity(error_type: &str, message: &str) -> Entity {
    let data = entity_ecf::to_ecf(&Value::Map(vec![
        (entity_ecf::text("type"), entity_ecf::text(error_type)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    Entity::new("system/protocol/error", data).expect("error entity")
}
