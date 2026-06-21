use std::collections::BTreeMap;

use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_hash::Hash;

// ---------------------------------------------------------------------------
// Constants (§9.3)
// ---------------------------------------------------------------------------

pub const PEER_DEFAULT_MAX_OPS: u64 = 100_000;
pub const PEER_DEFAULT_MAX_DEPTH: u64 = 1_024;
pub const CASCADE_DEPTH_COMPUTE_FREEZE: u32 = 16;

// ---------------------------------------------------------------------------
// Expression type names (§2.1, §2.2)
// ---------------------------------------------------------------------------

pub const TYPE_LITERAL: &str = "compute/literal";
pub const TYPE_LOOKUP_SCOPE: &str = "compute/lookup/scope";
pub const TYPE_LOOKUP_TREE: &str = "compute/lookup/tree";
pub const TYPE_APPLY: &str = "compute/apply";
pub const TYPE_IF: &str = "compute/if";
pub const TYPE_LET: &str = "compute/let";
pub const TYPE_LAMBDA: &str = "compute/lambda";
pub const TYPE_ARITHMETIC: &str = "compute/arithmetic";
pub const TYPE_COMPARE: &str = "compute/compare";
pub const TYPE_LOGIC: &str = "compute/logic";
pub const TYPE_FIELD: &str = "compute/field";
pub const TYPE_CONSTRUCT: &str = "compute/construct";
pub const TYPE_INDEX: &str = "compute/index";
pub const TYPE_LENGTH: &str = "compute/length";
pub const TYPE_NUMERIC_CAST: &str = "compute/numeric-cast";
pub const TYPE_LOOKUP_HASH: &str = "compute/lookup/hash";

// Args types for collection builtins (§3.5)
pub const TYPE_MAP_ARGS: &str = "system/compute/map-args";
pub const TYPE_FILTER_ARGS: &str = "system/compute/filter-args";
pub const TYPE_FOLD_ARGS: &str = "system/compute/fold-args";
pub const TYPE_STORE_ARGS: &str = "system/compute/store-args";

// Numeric primitive type names targeted by compute/numeric-cast `to_type` (§2.2)
pub const TYPE_PRIMITIVE_INT: &str = "primitive/int";
pub const TYPE_PRIMITIVE_UINT: &str = "primitive/uint";
pub const TYPE_PRIMITIVE_FLOAT: &str = "primitive/float";

// Value type names (§2.3, §2.4)
pub const TYPE_CLOSURE: &str = "compute/closure";
pub const TYPE_SCOPE: &str = "compute/scope";
pub const TYPE_RESULT: &str = "compute/result";
pub const TYPE_ERROR: &str = "compute/error";

// Subgraph metadata type (§2.5)
pub const TYPE_SUBGRAPH: &str = "system/compute/subgraph";

/// Check whether an entity belongs to the compute type set (§4.2 D2).
///
/// Includes expression types, value types, result/error types, and system types.
/// Used by resolve() to validate expression-graph membership.
pub fn is_compute_type(entity: &Entity) -> bool {
    is_compute_expression(entity)
        || matches!(
            entity.entity_type.as_str(),
            TYPE_CLOSURE
                | TYPE_SCOPE
                | TYPE_RESULT
                | TYPE_ERROR
                | TYPE_SUBGRAPH
                | "system/compute/install-request"
                | "system/compute/install-result"
        )
}

/// Check whether an entity is a compute expression (§4.7).
pub fn is_compute_expression(entity: &Entity) -> bool {
    matches!(
        entity.entity_type.as_str(),
        TYPE_LITERAL
            | TYPE_LOOKUP_SCOPE
            | TYPE_LOOKUP_TREE
            | TYPE_LOOKUP_HASH
            | TYPE_APPLY
            | TYPE_IF
            | TYPE_LET
            | TYPE_LAMBDA
            | TYPE_ARITHMETIC
            | TYPE_COMPARE
            | TYPE_LOGIC
            | TYPE_FIELD
            | TYPE_CONSTRUCT
            | TYPE_INDEX
            | TYPE_LENGTH
            | TYPE_NUMERIC_CAST
    )
}

// ---------------------------------------------------------------------------
// ComputeValue — evaluation result (§2.3, §2.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ComputeValue {
    Primitive(Value),
    Entity(Entity),
    Closure(ClosureValue),
    Error(ComputeError),
    /// Ephemeral uint-cast tag (§2.2 rule 11). Produced by
    /// `compute/numeric-cast → primitive/uint` and consumed by the
    /// **immediately-following** operation: `div`/`mod`/`compare` switch to
    /// unsigned interpretation when an operand carries this tag (rule 9).
    /// `add`/`sub`/`mul` ignore the tag — they are sign-agnostic at 64-bit
    /// two's-complement (rule 8) and never branch on operand kind. The tag
    /// does NOT flow through `compute/let` bindings (rule 11 explicitly
    /// pinned: "cast at the point of unsigned use, not at the point of value
    /// definition") — `eval_let` strips it before binding.
    Uint(u64),
}

/// Check if a value carries an active uint cast tag.
///
/// Per §2.2 rule 9: `div`/`mod`/`compare` switch to unsigned interpretation
/// when an operand is uint-tagged. Per rule 11 the tag is ephemeral and
/// consumed by the next operation — `eval_let` and any other binding form
/// strips it before storing in a scope.
pub fn is_uint_tagged(v: &ComputeValue) -> bool {
    matches!(v, ComputeValue::Uint(_))
}

/// Strip an ephemeral uint cast tag (rule 11). Used by binding forms (let,
/// closure args) so the tag does not flow through the binding. The value's
/// bit pattern is preserved by reinterpreting the u64 as i64 — encoded
/// canonically signed per rule 10.
pub fn strip_cast_tag(v: ComputeValue) -> ComputeValue {
    match v {
        ComputeValue::Uint(u) => ComputeValue::Primitive(entity_ecf::integer(u as i64)),
        other => other,
    }
}

impl ComputeValue {
    /// True for `ComputeValue::Error(_)` and for any `Entity` whose type is
    /// `compute/error` (v3.19b N6 / §3.2 — the NaN-propagation invariant from
    /// §1.5: a `compute/error` *value* is an error regardless of which variant
    /// holds it). Closes the case where a tree-stored `compute/error` reaches
    /// the evaluator as `ComputeValue::Entity` and would otherwise be treated
    /// as opaque data.
    pub fn is_error(&self) -> bool {
        match self {
            ComputeValue::Error(_) => true,
            ComputeValue::Entity(e) => e.entity_type == TYPE_ERROR,
            _ => false,
        }
    }

    /// Truthiness per §4.5.
    pub fn is_truthy(&self) -> bool {
        match self {
            ComputeValue::Primitive(v) => value_is_truthy(v),
            ComputeValue::Entity(_) => true,
            ComputeValue::Closure(_) => true,
            ComputeValue::Error(_) => false,
            ComputeValue::Uint(u) => *u != 0,
        }
    }

    pub fn as_primitive(&self) -> Option<&Value> {
        match self {
            ComputeValue::Primitive(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_entity(&self) -> Option<&Entity> {
        match self {
            ComputeValue::Entity(e) => Some(e),
            _ => None,
        }
    }

    /// Convert to an i128 if this is a primitive integer (signed or unsigned).
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            ComputeValue::Primitive(Value::Integer(i)) => Some((*i).into()),
            ComputeValue::Uint(u) => Some(*u as i128),
            _ => None,
        }
    }

    /// Convert to f64 if this is a primitive float.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            ComputeValue::Primitive(Value::Float(f)) => Some(*f),
            _ => None,
        }
    }

    /// Check if this is a numeric value (integer or float).
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            ComputeValue::Primitive(Value::Integer(_))
                | ComputeValue::Primitive(Value::Float(_))
                | ComputeValue::Uint(_)
        )
    }

    /// Check if this is a float value.
    pub fn is_float(&self) -> bool {
        matches!(self, ComputeValue::Primitive(Value::Float(_)))
    }

    /// Check if this is a string value.
    pub fn is_string(&self) -> bool {
        matches!(self, ComputeValue::Primitive(Value::Text(_)))
    }

    /// Convert a numeric value to f64 for float promotion.
    pub fn to_f64(&self) -> Option<f64> {
        match self {
            ComputeValue::Primitive(Value::Float(f)) => Some(*f),
            ComputeValue::Primitive(Value::Integer(i)) => {
                let n: i128 = (*i).into();
                Some(n as f64)
            }
            ComputeValue::Uint(u) => Some(*u as f64),
            _ => None,
        }
    }

    pub fn as_str_val(&self) -> Option<&str> {
        match self {
            ComputeValue::Primitive(Value::Text(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Build a compute/result entity from this value (§2.4).
    pub fn to_result_entity(&self, expression_hash: &Hash) -> Entity {
        match self {
            ComputeValue::Entity(e) => e.clone(),
            ComputeValue::Error(err) => err.to_entity(),
            ComputeValue::Primitive(v) => {
                let data = entity_ecf::cbor_map! {
                    "expression" => Value::Bytes(expression_hash.to_bytes().to_vec()),
                    "value" => v.clone()
                };
                let data_bytes = entity_ecf::to_ecf(&data);
                Entity::new(TYPE_RESULT, data_bytes).expect("result entity")
            }
            ComputeValue::Closure(c) => c.to_entity(),
            ComputeValue::Uint(u) => {
                // Per §2.2 rule 10's "result intended as unsigned" clause: a
                // value explicitly produced by `numeric-cast → uint` encodes as
                // a genuinely non-negative number (CBOR major type 0).
                let data = entity_ecf::cbor_map! {
                    "expression" => Value::Bytes(expression_hash.to_bytes().to_vec()),
                    "value" => Value::Integer(ciborium::value::Integer::from(*u))
                };
                let data_bytes = entity_ecf::to_ecf(&data);
                Entity::new(TYPE_RESULT, data_bytes).expect("result entity")
            }
        }
    }
}

/// Truthiness for a raw CBOR value (§4.5).
fn value_is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            n != 0
        }
        Value::Text(s) => !s.is_empty(),
        Value::Array(arr) => !arr.is_empty(),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// ClosureValue (§2.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ClosureValue {
    pub params: Vec<String>,
    pub body: Hash,
    pub env: Option<Hash>,
}

impl ClosureValue {
    pub fn to_entity(&self) -> Entity {
        let mut fields = vec![
            (
                Value::Text("body".into()),
                Value::Bytes(self.body.to_bytes().to_vec()),
            ),
            (
                Value::Text("params".into()),
                Value::Array(self.params.iter().map(|p| Value::Text(p.clone())).collect()),
            ),
        ];
        if let Some(ref env) = self.env {
            fields.push((
                Value::Text("env".into()),
                Value::Bytes(env.to_bytes().to_vec()),
            ));
        }
        let data = Value::Map(fields);
        let data_bytes = entity_ecf::to_ecf(&data);
        Entity::new(TYPE_CLOSURE, data_bytes).expect("closure entity")
    }
}

// ---------------------------------------------------------------------------
// Scope (§4.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Scope {
    pub bindings: BTreeMap<String, ComputeValue>,
}

impl Scope {
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    pub fn has(&self, name: &str) -> bool {
        self.bindings.contains_key(name)
    }

    pub fn get(&self, name: &str) -> Option<&ComputeValue> {
        self.bindings.get(name)
    }

    pub fn set(&mut self, name: String, value: ComputeValue) {
        self.bindings.insert(name, value);
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Budget (§5.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Budget {
    pub operations: u64,
    pub depth: u64,
}

impl Budget {
    pub fn new(operations: u64, depth: u64) -> Self {
        Self { operations, depth }
    }

    pub fn default_budget() -> Self {
        Self::new(PEER_DEFAULT_MAX_OPS, PEER_DEFAULT_MAX_DEPTH)
    }
}

// ---------------------------------------------------------------------------
// ComputeError (§9.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ComputeError {
    BudgetExhausted,
    DepthExceeded,
    TypeMismatch(String),
    DivisionByZero,
    NotFound(String),
    UnknownType(String),
    MissingArgument(String),
    InvalidExpression(String),
    CascadeLimit,
    PermissionDenied(String),
    InstallationGrantInvalid(String),
    IndexOutOfRange(String),
    CastOutOfRange(String),
    /// v3.19b N8: a `kind:"entity"` scope binding's hash resolves in neither the
    /// local content store nor the envelope `included`. Error-as-value at
    /// status 200 (F10), not transport failure.
    ScopeUnreachable(String),
}

impl ComputeError {
    pub fn code(&self) -> &str {
        match self {
            ComputeError::BudgetExhausted => "budget_exhausted",
            ComputeError::DepthExceeded => "depth_exceeded",
            ComputeError::TypeMismatch(_) => "type_mismatch",
            ComputeError::DivisionByZero => "division_by_zero",
            ComputeError::NotFound(_) => "not_found",
            ComputeError::UnknownType(_) => "unknown_type",
            ComputeError::MissingArgument(_) => "missing_argument",
            ComputeError::InvalidExpression(_) => "invalid_expression",
            ComputeError::CascadeLimit => "cascade_limit",
            ComputeError::PermissionDenied(_) => "permission_denied",
            ComputeError::InstallationGrantInvalid(_) => "installation_grant_invalid",
            ComputeError::IndexOutOfRange(_) => "index_out_of_range",
            ComputeError::CastOutOfRange(_) => "cast_out_of_range",
            ComputeError::ScopeUnreachable(_) => "scope_unreachable",
        }
    }

    pub fn message(&self) -> String {
        match self {
            ComputeError::BudgetExhausted => "Computation budget exhausted".into(),
            ComputeError::DepthExceeded => "Maximum evaluation depth exceeded".into(),
            ComputeError::TypeMismatch(msg) => msg.clone(),
            ComputeError::DivisionByZero => "Division or modulo by zero".into(),
            ComputeError::NotFound(msg) => msg.clone(),
            ComputeError::UnknownType(msg) => msg.clone(),
            ComputeError::MissingArgument(msg) => msg.clone(),
            ComputeError::InvalidExpression(msg) => msg.clone(),
            ComputeError::CascadeLimit => {
                "Cascade depth exceeded during reactive re-evaluation".into()
            }
            ComputeError::PermissionDenied(msg) => msg.clone(),
            ComputeError::InstallationGrantInvalid(msg) => msg.clone(),
            ComputeError::IndexOutOfRange(msg) => msg.clone(),
            ComputeError::CastOutOfRange(msg) => msg.clone(),
            ComputeError::ScopeUnreachable(msg) => msg.clone(),
        }
    }

    pub fn to_entity(&self) -> Entity {
        let data = entity_ecf::cbor_map! {
            "code" => Value::Text(self.code().into()),
            "message" => Value::Text(self.message())
        };
        let data_bytes = entity_ecf::to_ecf(&data);
        Entity::new(TYPE_ERROR, data_bytes).expect("error entity")
    }

    pub fn to_value(&self) -> ComputeValue {
        ComputeValue::Error(self.clone())
    }
}

impl std::fmt::Display for ComputeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

// ---------------------------------------------------------------------------
// CBOR data helpers
// ---------------------------------------------------------------------------

/// Decode entity data bytes into a ciborium Value.
pub fn decode_data(entity: &Entity) -> Option<Value> {
    ciborium::de::from_reader::<Value, _>(entity.data.as_slice()).ok()
}

/// Extract a string field from entity data.
pub fn data_str(data: &Value, key: &str) -> Option<String> {
    data.get(key)?.as_str().map(|s| s.to_string())
}

/// Extract a Hash from a bytes field in entity data.
pub fn data_hash(data: &Value, key: &str) -> Option<Hash> {
    let bytes = data.get(key)?.as_bytes()?;
    Hash::from_bytes(bytes).ok()
}

/// Extract a bool field from entity data.
pub fn data_bool(data: &Value, key: &str) -> Option<bool> {
    match data.get(key)? {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

/// Extract a string array from entity data.
pub fn data_str_array(data: &Value, key: &str) -> Option<Vec<String>> {
    let arr = data.get(key)?.as_array()?;
    arr.iter()
        .map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
}

/// Extract the entries of a map field as (String, Value) pairs.
pub fn data_map_entries(data: &Value, key: &str) -> Option<Vec<(String, Value)>> {
    let map = data.get(key)?;
    if let Value::Map(entries) = map {
        let mut result = Vec::new();
        for (k, v) in entries {
            if let Value::Text(s) = k {
                result.push((s.clone(), v.clone()));
            }
        }
        Some(result)
    } else {
        None
    }
}

/// Extract a map field where values are hashes (bytes).
pub fn data_hash_map(data: &Value, key: &str) -> Option<Vec<(String, Hash)>> {
    let map = data.get(key)?;
    if let Value::Map(entries) = map {
        let mut result = Vec::new();
        for (k, v) in entries {
            if let Value::Text(name) = k {
                if let Some(bytes) = v.as_bytes() {
                    if let Ok(h) = Hash::from_bytes(bytes) {
                        result.push((name.clone(), h));
                    }
                }
            }
        }
        Some(result)
    } else {
        None
    }
}
