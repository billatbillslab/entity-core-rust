//! system/history handler — query and rollback operations.
//!
//! Provides history traversal and rollback for paths with history enabled.
//! History transitions are recorded by the HistoryEngine (engine.rs).

pub mod engine;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_FORBIDDEN,
    STATUS_NOT_FOUND,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::engine::canonicalize_pattern;

// ---------------------------------------------------------------------------
// HistoryHandler
// ---------------------------------------------------------------------------

pub struct HistoryHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
}

impl HistoryHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/history", local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for HistoryHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "query" => self.handle_query(ctx),
            "rollback" => self.handle_rollback(ctx),
            other => Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity("unknown_operation", &format!("unknown operation: {}", other)),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "history"
    }

    fn operations(&self) -> &[&str] {
        &["query", "rollback"]
    }
}

impl HistoryHandler {
    fn handle_query(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_params(ctx)?;

        let raw_path = params.path;
        let path = self.canonicalize_path(&raw_path);

        // Dual capability check: target path requires "get" access
        if let Some(ref cap) = ctx.caller_capability {
            if !entity_capability::check_permission(
                "get",
                &format!("/{}/system/tree", self.local_peer_id),
                &self.local_peer_id,
                Some(&entity_capability::ResourceTarget {
                    targets: vec![path.clone()],
                    exclude: vec![],
                }),
                cap,
                &self.local_peer_id,
            ) {
                return Ok(HandlerResult::error(
                    STATUS_FORBIDDEN,
                    error_entity("access_denied", "insufficient capability for target path"),
                ));
            }
        }

        let head_pointer_path = format!(
            "/{}/system/history/head{}",
            self.local_peer_id, path
        );
        let head_hash = self.location_index.get(&head_pointer_path);

        if head_hash.is_none() {
            // No history for this path
            let result = build_query_result(&path, None, vec![], false);
            let envelope = build_envelope_result(result, HashMap::new());
            return Ok(HandlerResult::ok(envelope));
        }
        let head_hash = head_hash.unwrap();

        let limit = params.limit.unwrap_or(50) as usize;
        let mut transitions = Vec::new();
        let mut current_hash = Some(head_hash);
        let mut has_more = false;

        while let Some(hash) = current_hash {
            let entity = match self.content_store.get(&hash) {
                Some(e) => e,
                None => break,
            };

            let transition_data = match decode_transition(&entity) {
                Some(t) => t,
                None => break,
            };

            // Check "since" filter — stop when we hit this hash
            if let Some(ref since) = params.since {
                if hash == *since {
                    break;
                }
            }

            // Check "before" filter — skip transitions at or after this timestamp
            if let Some(before) = params.before {
                if transition_data.timestamp >= before {
                    current_hash = transition_data.previous;
                    continue;
                }
            }

            // Check event type filter
            if let Some(ref event_filter) = params.events {
                if !event_filter.iter().any(|e| e == &transition_data.event) {
                    current_hash = transition_data.previous;
                    continue;
                }
            }

            if transitions.len() >= limit {
                has_more = true;
                break;
            }

            transitions.push((hash, entity));
            current_hash = transition_data.previous;
        }

        if current_hash.is_some() && !has_more {
            has_more = true;
        }

        // Build included map and inline transition data for the result
        let mut included = HashMap::new();
        let mut transition_values = Vec::new();
        for (hash, entity) in transitions {
            // Decode entity data to inline CBOR map for the transitions array (spec §2.4)
            if let Ok(val) = ciborium::from_reader::<entity_ecf::Value, _>(entity.data.as_slice()) {
                transition_values.push(val);
            }
            included.insert(hash, entity);
        }

        let result = build_query_result(
            &path,
            Some(head_hash),
            transition_values,
            has_more,
        );
        let envelope = build_envelope_result(result, included);
        Ok(HandlerResult::ok(envelope))
    }

    fn handle_rollback(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_rollback_params(ctx)?;

        let raw_path = params.path;
        let path = self.canonicalize_path(&raw_path);
        let target_hash = params.target_hash;

        // Dual capability check: rollback requires "put" access to target path
        if let Some(ref cap) = ctx.caller_capability {
            if !entity_capability::check_permission(
                "put",
                &format!("/{}/system/tree", self.local_peer_id),
                &self.local_peer_id,
                Some(&entity_capability::ResourceTarget {
                    targets: vec![path.clone()],
                    exclude: vec![],
                }),
                cap,
                &self.local_peer_id,
            ) {
                return Ok(HandlerResult::error(
                    STATUS_FORBIDDEN,
                    error_entity("access_denied", "insufficient capability for target path"),
                ));
            }
        }

        // Validate target_hash is in the path's history
        if !self.is_in_history(&path, &target_hash) {
            return Ok(HandlerResult::error(
                STATUS_NOT_FOUND,
                error_entity(
                    "not_in_history",
                    "target hash not found in history for this path",
                ),
            ));
        }

        // Verify entity exists in content store
        if !self.content_store.has(&target_hash) {
            return Ok(HandlerResult::error(
                STATUS_NOT_FOUND,
                error_entity("entity_not_found", "target entity not in content store"),
            ));
        }

        // Restore by rebinding the path to the old entity's hash.
        // This goes through normal set, which will itself be recorded in history.
        self.location_index.set(&path, target_hash);

        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("path"), entity_ecf::text(&path)),
            (
                entity_ecf::text("restored"),
                entity_ecf::Value::Bytes(target_hash.to_bytes().to_vec()),
            ),
        ]));
        let result =
            Entity::new(entity_types::TYPE_HISTORY_ROLLBACK_RESULT, result_data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(result))
    }

    fn canonicalize_path(&self, path: &str) -> String {
        canonicalize_pattern(path, &self.local_peer_id)
    }

    /// Check if a target_hash appears in the history chain for a path.
    fn is_in_history(&self, path: &str, target_hash: &Hash) -> bool {
        let head_pointer_path = format!(
            "/{}/system/history/head{}",
            self.local_peer_id, path
        );
        let mut current = self.location_index.get(&head_pointer_path);

        while let Some(hash) = current {
            let entity = match self.content_store.get(&hash) {
                Some(e) => e,
                None => break,
            };
            let transition = match decode_transition(&entity) {
                Some(t) => t,
                None => break,
            };

            if transition.hash.as_ref() == Some(target_hash)
                || transition.previous_hash.as_ref() == Some(target_hash)
            {
                return true;
            }

            current = transition.previous;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Params decoding
// ---------------------------------------------------------------------------

struct QueryParams {
    path: String,
    limit: Option<u64>,
    since: Option<Hash>,
    before: Option<u64>,
    events: Option<Vec<String>>,
}

struct RollbackParams {
    path: String,
    target_hash: Hash,
}

fn decode_params(ctx: &HandlerContext) -> Result<QueryParams, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(ctx.params.data.as_slice())
        .map_err(|e| HandlerError::InvalidParams(format!("invalid CBOR: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params must be a map".into()))?;

    let path = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("path"))
        .and_then(|(_, v)| v.as_text())
        .ok_or_else(|| HandlerError::InvalidParams("path is required".into()))?
        .to_string();

    let limit = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("limit"))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| u64::try_from(i).ok());

    let since = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("since"))
        .and_then(|(_, v)| v.as_bytes())
        .and_then(|b| Hash::from_bytes(b).ok());

    let before = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("before"))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| u64::try_from(i).ok());

    let events = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("events"))
        .and_then(|(_, v)| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_text().map(|s| s.to_string()))
                .collect()
        });

    Ok(QueryParams {
        path,
        limit,
        since,
        before,
        events,
    })
}

fn decode_rollback_params(ctx: &HandlerContext) -> Result<RollbackParams, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(ctx.params.data.as_slice())
        .map_err(|e| HandlerError::InvalidParams(format!("invalid CBOR: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params must be a map".into()))?;

    let path = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("path"))
        .and_then(|(_, v)| v.as_text())
        .ok_or_else(|| HandlerError::InvalidParams("path is required".into()))?
        .to_string();

    let target_hash = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("target_hash"))
        .and_then(|(_, v)| v.as_bytes())
        .and_then(|b| Hash::from_bytes(b).ok())
        .ok_or_else(|| HandlerError::InvalidParams("target_hash is required".into()))?;

    Ok(RollbackParams { path, target_hash })
}

// ---------------------------------------------------------------------------
// Transition decoding
// ---------------------------------------------------------------------------

struct TransitionData {
    event: String,
    hash: Option<Hash>,
    previous_hash: Option<Hash>,
    timestamp: u64,
    previous: Option<Hash>,
}

fn decode_transition(entity: &Entity) -> Option<TransitionData> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;

    let event = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("event"))
        .and_then(|(_, v)| v.as_text())
        .unwrap_or("")
        .to_string();

    let hash = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("hash"))
        .and_then(|(_, v)| v.as_bytes())
        .and_then(|b| Hash::from_bytes(b).ok());

    let previous_hash = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("previous_hash"))
        .and_then(|(_, v)| v.as_bytes())
        .and_then(|b| Hash::from_bytes(b).ok());

    let timestamp = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("timestamp"))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| u64::try_from(i).ok())
        .unwrap_or(0);

    let previous = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("previous"))
        .and_then(|(_, v)| v.as_bytes())
        .and_then(|b| Hash::from_bytes(b).ok());

    Some(TransitionData {
        event,
        hash,
        previous_hash,
        timestamp,
        previous,
    })
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

fn build_query_result(
    path: &str,
    head: Option<Hash>,
    transition_values: Vec<entity_ecf::Value>,
    has_more: bool,
) -> Entity {
    let mut fields = vec![(entity_ecf::text("path"), entity_ecf::text(path))];

    if let Some(h) = head {
        fields.push((
            entity_ecf::text("head"),
            entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }

    fields.push((
        entity_ecf::text("transitions"),
        entity_ecf::Value::Array(transition_values),
    ));
    fields.push((
        entity_ecf::text("has_more"),
        entity_ecf::bool_val(has_more),
    ));

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    Entity::new(entity_types::TYPE_HISTORY_QUERY_RESULT, data)
        .expect("query result entity creation should not fail")
}

fn entity_to_inline(entity: &Entity) -> entity_ecf::Value {
    let data_value: entity_ecf::Value = ciborium::from_reader(entity.data.as_slice())
        .unwrap_or(entity_ecf::Value::Null);
    entity_ecf::Value::Map(vec![
        (entity_ecf::text("content_hash"), entity_ecf::Value::Bytes(entity.content_hash.to_bytes().to_vec())),
        (entity_ecf::text("data"), data_value),
        (entity_ecf::text("type"), entity_ecf::text(&entity.entity_type)),
    ])
}

fn build_envelope_result(root: Entity, included: HashMap<Hash, Entity>) -> Entity {
    let included_entries: Vec<_> = included
        .iter()
        .map(|(hash, entity)| {
            (entity_ecf::Value::Bytes(hash.to_bytes().to_vec()), entity_to_inline(entity))
        })
        .collect();

    let mut envelope_fields = vec![(entity_ecf::text("root"), entity_to_inline(&root))];
    if !included_entries.is_empty() {
        envelope_fields.push((
            entity_ecf::text("included"),
            entity_ecf::Value::Map(included_entries),
        ));
    }

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(envelope_fields));
    Entity::new(entity_types::TYPE_ENVELOPE, data)
        .expect("envelope entity creation should not fail")
}

fn error_entity(code: &str, message: &str) -> Entity {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    Entity::new(entity_types::TYPE_ERROR, data).expect("error entity creation should not fail")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id() -> String {
        "TestPeerABCDEFGH1234567890abcdefghijklmnop123".to_string()
    }

    fn make_handler() -> HistoryHandler {
        let store = Arc::new(MemoryContentStore::new());
        let li = Arc::new(MemoryLocationIndex::new());
        HistoryHandler::new(store, li, test_peer_id())
    }

    fn make_ctx(handler: &HistoryHandler, operation: &str, params: Entity) -> HandlerContext {
        let execute_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("request_id"), entity_ecf::text("test-req")),
        ]));
        let execute = Entity::new(entity_types::TYPE_EXECUTE, execute_data).unwrap();
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            pattern: handler.qualified_pattern.clone(),
            suffix: String::new(),
            resource_target: None,
            author: None,
            session_peer_id: None,
            request_id: "test-req".to_string(),
            operation: operation.to_string(),
            execute_fn: None,
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        }
    }

    /// Extract the root entity's data bytes from an envelope result entity.
    /// Data is embedded as a raw CBOR value (not a byte string), so we
    /// re-encode it to get bytes for further decoding.
    fn unwrap_envelope_root_data(envelope: &Entity) -> Vec<u8> {
        assert_eq!(envelope.entity_type, entity_types::TYPE_ENVELOPE);
        let val: ciborium::Value =
            ciborium::from_reader(envelope.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let root = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("root"))
            .unwrap()
            .1
            .as_map()
            .unwrap();
        let data_value = &root
            .iter()
            .find(|(k, _)| k.as_text() == Some("data"))
            .unwrap()
            .1;
        let mut buf = Vec::new();
        ciborium::into_writer(data_value, &mut buf).unwrap();
        buf
    }

    /// Count the included entities inside an envelope result entity.
    fn envelope_included_count(envelope: &Entity) -> usize {
        let val: ciborium::Value =
            ciborium::from_reader(envelope.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        match map.iter().find(|(k, _)| k.as_text() == Some("included")) {
            Some((_, v)) => v.as_map().unwrap().len(),
            None => 0,
        }
    }

    fn store_transition(
        handler: &HistoryHandler,
        path: &str,
        event: &str,
        entity_hash: Option<Hash>,
        previous: Option<Hash>,
    ) -> Hash {
        let mut fields = vec![
            (entity_ecf::text("path"), entity_ecf::text(path)),
            (entity_ecf::text("event"), entity_ecf::text(event)),
            (
                entity_ecf::text("author"),
                entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("capability"),
                entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec()),
            ),
            (entity_ecf::text("handler"), entity_ecf::text("")),
            (entity_ecf::text("operation"), entity_ecf::text("put")),
            (entity_ecf::text("timestamp"), entity_ecf::integer(1000)),
        ];
        if let Some(h) = entity_hash {
            fields.push((
                entity_ecf::text("hash"),
                entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
            ));
        }
        if let Some(prev) = previous {
            fields.push((
                entity_ecf::text("previous"),
                entity_ecf::Value::Bytes(prev.to_bytes().to_vec()),
            ));
        }
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let entity =
            Entity::new(entity_types::TYPE_HISTORY_TRANSITION, data).unwrap();
        handler.content_store.put(entity).unwrap()
    }

    #[tokio::test]
    async fn test_query_empty_history() {
        let handler = make_handler();
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("path"),
            entity_ecf::text("docs/readme"),
        )]));
        let params =
            Entity::new(entity_types::TYPE_HISTORY_QUERY_PARAMS, params_data).unwrap();
        let ctx = make_ctx(&handler, "query", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.result.entity_type, entity_types::TYPE_ENVELOPE);

        let root_data = unwrap_envelope_root_data(&result.result);
        let val: ciborium::Value =
            ciborium::from_reader(root_data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let transitions = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("transitions"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert!(transitions.is_empty());
    }

    #[tokio::test]
    async fn test_query_with_chain() {
        let handler = make_handler();
        let pid = test_peer_id();
        let path = format!("/{}/docs/readme", pid);

        let entity_hash = Hash::compute("test", b"content");

        // Build a chain: t1 -> t2 -> t3 (t3 is head)
        let t1 = store_transition(&handler, &path, "created", Some(entity_hash), None);
        let t2 = store_transition(&handler, &path, "updated", Some(entity_hash), Some(t1));
        let t3 = store_transition(&handler, &path, "updated", Some(entity_hash), Some(t2));

        // Set head pointer
        let head_path = format!("/{}/system/history/head{}", pid, path);
        handler.location_index.set(&head_path, t3);

        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("path"),
            entity_ecf::text(&path),
        )]));
        let params =
            Entity::new(entity_types::TYPE_HISTORY_QUERY_PARAMS, params_data).unwrap();
        let ctx = make_ctx(&handler, "query", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.result.entity_type, entity_types::TYPE_ENVELOPE);

        let root_data = unwrap_envelope_root_data(&result.result);
        let val: ciborium::Value =
            ciborium::from_reader(root_data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let transitions = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("transitions"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(transitions.len(), 3);

        // Transitions must be inline CBOR maps, not byte strings (spec §2.4, issue #15)
        for t in transitions {
            assert!(t.as_map().is_some(), "transition must be an inline map, not {:?}", t);
        }

        // Envelope included map should contain the 3 transition entities
        assert_eq!(envelope_included_count(&result.result), 3);
    }

    #[tokio::test]
    async fn test_query_limit() {
        let handler = make_handler();
        let pid = test_peer_id();
        let path = format!("/{}/docs/readme", pid);

        let entity_hash = Hash::compute("test", b"content");
        let t1 = store_transition(&handler, &path, "created", Some(entity_hash), None);
        let t2 = store_transition(&handler, &path, "updated", Some(entity_hash), Some(t1));
        let t3 = store_transition(&handler, &path, "updated", Some(entity_hash), Some(t2));

        let head_path = format!("/{}/system/history/head{}", pid, path);
        handler.location_index.set(&head_path, t3);

        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("path"), entity_ecf::text(&path)),
            (entity_ecf::text("limit"), entity_ecf::integer(2)),
        ]));
        let params =
            Entity::new(entity_types::TYPE_HISTORY_QUERY_PARAMS, params_data).unwrap();
        let ctx = make_ctx(&handler, "query", params);
        let result = handler.handle(&ctx).await.unwrap();

        let root_data = unwrap_envelope_root_data(&result.result);
        let val: ciborium::Value =
            ciborium::from_reader(root_data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let transitions = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("transitions"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(transitions.len(), 2);

        let has_more = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("has_more"))
            .unwrap()
            .1
            .as_bool()
            .unwrap();
        assert!(has_more);
    }

    #[tokio::test]
    async fn test_rollback_restores_binding() {
        let handler = make_handler();
        let pid = test_peer_id();
        let path = format!("/{}/docs/readme", pid);

        // Store an entity at the path
        let original_data = entity_ecf::to_ecf(&entity_ecf::text("original"));
        let original = Entity::new("test/doc", original_data).unwrap();
        let original_hash = handler.content_store.put(original).unwrap();
        handler.location_index.set(&path, original_hash);

        // Store a different entity
        let new_data = entity_ecf::to_ecf(&entity_ecf::text("modified"));
        let new_entity = Entity::new("test/doc", new_data).unwrap();
        let new_hash = handler.content_store.put(new_entity).unwrap();
        handler.location_index.set(&path, new_hash);

        // Build history chain: created(original) -> updated(new)
        let t1 = store_transition(&handler, &path, "created", Some(original_hash), None);
        let t2 = store_transition(&handler, &path, "updated", Some(new_hash), Some(t1));
        let head_path = format!("/{}/system/history/head{}", pid, path);
        handler.location_index.set(&head_path, t2);

        // Rollback to original
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("path"), entity_ecf::text(&path)),
            (
                entity_ecf::text("target_hash"),
                entity_ecf::Value::Bytes(original_hash.to_bytes().to_vec()),
            ),
        ]));
        let params =
            Entity::new(entity_types::TYPE_HISTORY_ROLLBACK_PARAMS, params_data).unwrap();
        let ctx = make_ctx(&handler, "rollback", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, 200);

        // Verify path is now bound to original
        assert_eq!(handler.location_index.get(&path), Some(original_hash));
    }

    #[tokio::test]
    async fn test_rollback_rejects_unknown_hash() {
        let handler = make_handler();
        let pid = test_peer_id();
        let path = format!("/{}/docs/readme", pid);

        // No history for this path
        let unknown_hash = Hash::compute("test", b"unknown");

        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("path"), entity_ecf::text(&path)),
            (
                entity_ecf::text("target_hash"),
                entity_ecf::Value::Bytes(unknown_hash.to_bytes().to_vec()),
            ),
        ]));
        let params =
            Entity::new(entity_types::TYPE_HISTORY_ROLLBACK_PARAMS, params_data).unwrap();
        let ctx = make_ctx(&handler, "rollback", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }
}
