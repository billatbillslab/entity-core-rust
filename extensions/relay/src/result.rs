//! Handler result + error builders. Relay results are **flat typed entities**
//! (`forward-result` / `put-result` / `poll-result`), never wrapped in
//! `system/protocol/status` (handoff §3). Errors use the standard V7 ERROR
//! shape and are fail-closed (§4.3 — no partial effect on error).

use std::collections::HashMap;

use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::{HandlerResult, STATUS_OK};

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

/// Wrap a flat relay result entity as a 200 `HandlerResult`, optionally
/// carrying `included` entities (e.g. the stored store-entry + inner envelope
/// so a co-located caller can fetch them; content-addressed, so over-inclusion
/// is free).
pub(crate) fn ok_result(result: Entity, included: HashMap<entity_hash::Hash, Entity>) -> HandlerResult {
    HandlerResult {
        status: STATUS_OK,
        result,
        included,
    }
}
