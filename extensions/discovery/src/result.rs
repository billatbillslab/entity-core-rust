//! Shared handler result + error entity builders (mirrors
//! `extensions/registry/src/result.rs`).

use std::collections::HashMap;

use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::HandlerResult;

pub(crate) fn make_error_entity(code: &str, message: &str) -> Entity {
    let data = to_ecf(&Value::Map(vec![
        (text("code"), text(code)),
        (text("message"), text(message)),
    ]));
    Entity::new(entity_types::TYPE_ERROR, data).expect("error entity")
}

pub(crate) fn error(status: u32, code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(status, make_error_entity(code, message))
}

/// Build a `system/protocol/status` result entity from CBOR map fields.
pub(crate) fn status_result(fields: Vec<(Value, Value)>) -> HandlerResult {
    let result = Entity::new(entity_types::TYPE_PROTOCOL_STATUS, to_ecf(&Value::Map(fields)))
        .expect("status entity");
    HandlerResult {
        status: entity_handler::STATUS_OK,
        result,
        included: HashMap::new(),
    }
}
