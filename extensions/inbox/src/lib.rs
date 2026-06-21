//! system/inbox handler — message delivery and continuation integration.
//!
//! Per spec: receives messages at a resource path, stores them in the tree,
//! and optionally advances continuations if one exists at the inbox path.

use std::sync::Arc;

use async_trait::async_trait;
use entity_entity::Entity;

// Platform-aware task spawning: tokio::spawn on native, wasm_bindgen_futures::spawn_local on WASM.
#[cfg(not(target_arch = "wasm32"))]
fn spawn_task<F: std::future::Future<Output = ()> + Send + 'static>(f: F) {
    tokio::spawn(f);
}
#[cfg(target_arch = "wasm32")]
fn spawn_task<F: std::future::Future<Output = ()> + 'static>(f: F) {
    wasm_bindgen_futures::spawn_local(f);
}
use entity_handler::{
    ExecuteOptions, Handler, HandlerContext, HandlerError, HandlerResult,
    STATUS_BAD_REQUEST, STATUS_OK,
};
use entity_store::{ContentStore, LocationIndex};

/// The inbox handler: system/inbox with operation "receive".
pub struct InboxHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    qualified_pattern: String,
}

impl InboxHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/inbox", local_peer_id);
        Self {
            content_store,
            location_index,
            qualified_pattern,
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for InboxHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "receive" => self.handle_receive(ctx).await,
            _ => Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                make_error_entity("unknown_operation", &format!("unknown: {}", ctx.operation)),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "inbox"
    }

    fn operations(&self) -> &[&str] {
        &["receive"]
    }
}

impl InboxHandler {
    async fn handle_receive(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // Extract path from resource target
        let path = match ctx.resource_target.as_ref().and_then(|r| r.targets.first()) {
            Some(p) if !p.is_empty() => p.clone(),
            _ => {
                tracing::debug!(request_id = %ctx.request_id, "inbox receive: missing resource target path");
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    make_error_entity("invalid_params", "resource target path required"),
                ));
            }
        };

        tracing::debug!(
            request_id = %ctx.request_id,
            path = %path,
            params_type = %ctx.params.entity_type,
            "inbox receive"
        );

        // Params entity is pre-extracted by the dispatch layer
        let params_entity = ctx.params.clone();

        // Storage key = request_id, storage path = {path}/{key}
        let storage_key = if ctx.request_id.is_empty() {
            format!("{}", ctx.execute.content_hash)
        } else {
            ctx.request_id.clone()
        };
        let storage_path = format!("{}/{}", path, storage_key);

        // Write-ahead: store the message entity and index it.
        //
        // **Convergence assumption (PROPOSAL-CROSS-IMPL-STANDARDIZATION-
        // CATCHUP §6 latent-hole tracking):** `storage_path` is derived
        // from `request_id`, which is required to be unique per logical
        // message per V7 §6.8. The unconditional `set` is safe under this
        // uniqueness contract — two concurrent deliveries with the same
        // request_id are an upstream protocol violation, not a convergence
        // event. If inbox is ever repurposed as a peer-mirroring surface
        // (where the SAME logical message could legitimately arrive twice
        // with the same request_id from independently-converging peers),
        // this set needs the receiver-local CAS/convergent-mirroring
        // primitive (Go track) instead.
        let stored_hash = self
            .content_store
            .put(params_entity.clone())
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        self.location_index.set(&storage_path, stored_hash);

        tracing::debug!(
            request_id = %ctx.request_id,
            storage_path = %storage_path,
            hash = %stored_hash,
            "inbox receive: message stored"
        );

        // Check for continuation at the inbox path.
        // If found, spawn the advance asynchronously to avoid deadlock —
        // continuation dispatch may make remote calls that block if the
        // serve loop is occupied (same rationale as Go's goroutine approach).
        if let Some(cont_hash) = self.location_index.get(&path) {
            if let Some(cont_entity) = self.content_store.get(&cont_hash) {
                if cont_entity.entity_type == "system/continuation"
                    || cont_entity.entity_type == "system/continuation/join"
                {
                    if let Some(execute_fn) = &ctx.execute_fn {
                        let execute_fn = execute_fn.clone();
                        let path = path.clone();
                        let params_entity = params_entity.clone();
                        let storage_path = storage_path.clone();
                        let location_index = self.location_index.clone();

                        tracing::debug!(path = %path, "inbox: continuation found, spawning async advance");
                        spawn_task(async move {
                            let advance_result = try_advance_continuation_async(
                                &execute_fn,
                                &path,
                                &params_entity,
                                &storage_path,
                                &location_index,
                            )
                            .await;
                            if advance_result {
                                tracing::debug!(path = %path, "inbox: async continuation advanced");
                            }
                        });

                        // Return 200 immediately — advance runs in background
                        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                            entity_ecf::text("accepted"),
                            entity_ecf::Value::Bool(true),
                        )]));
                        let result_entity =
                            Entity::new("system/inbox/receive-result", result_data)
                                .map_err(|e| HandlerError::Internal(e.to_string()))?;
                        return Ok(HandlerResult {
                            status: STATUS_OK,
                            result: result_entity,
                            included: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }

        // Mailbox fallback: return receipt
        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("content_hash"),
                entity_ecf::Value::Bytes(stored_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("path"),
                entity_ecf::text(&storage_path),
            ),
        ]));
        let result_entity = Entity::new("system/inbox/receive-result", result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        Ok(HandlerResult {
            status: STATUS_OK,
            result: result_entity,
        included: std::collections::HashMap::new(),
        })
    }

}

/// Advance a continuation asynchronously (runs in a spawned task).
/// Returns true if advanced successfully, false otherwise.
async fn try_advance_continuation_async(
    execute_fn: &entity_handler::ExecuteFn,
    path: &str,
    params_entity: &Entity,
    storage_path: &str,
    location_index: &Arc<dyn LocationIndex>,
) -> bool {
    // Per INBOX spec §3.2: unwrap InboxDeliveryData before advancing.
    let (result_bytes, status) =
        if params_entity.entity_type == "system/protocol/inbox/delivery" {
            extract_delivery_fields(&params_entity.data)
                .unwrap_or_else(|| (params_entity.data.clone(), STATUS_OK))
        } else {
            (params_entity.data.clone(), STATUS_OK)
        };

    // Build advance request: {result: <inline value>, status: <status>}
    // The result is embedded as an inline CBOR value (not byte-string wrapped)
    // so the continuation handler sees the actual structure for inject mode.
    let result_value: entity_ecf::Value =
        ciborium::from_reader(result_bytes.as_slice()).unwrap_or(entity_ecf::Value::Null);
    let mut advance_fields = vec![(entity_ecf::text("result"), result_value)];
    if status != STATUS_OK {
        advance_fields.push((
            entity_ecf::text("status"),
            entity_ecf::integer(status as i64),
        ));
    }
    let advance_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(advance_fields));
    let advance_entity = match Entity::new("system/continuation/advance-request", advance_data) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "inbox: failed to build advance request");
            return false;
        }
    };

    let opts = ExecuteOptions {
        resource: Some(entity_capability::ResourceTarget {
            targets: vec![path.to_string()],
            exclude: vec![],
        }),
        ..Default::default()
    };

    tracing::debug!(path = %path, "inbox: attempting continuation advance");
    match execute_fn(
        "system/continuation".to_string(),
        "advance".to_string(),
        advance_entity,
        opts,
    )
    .await
    {
        Ok(result) => {
            if check_advanced(&result.result) {
                tracing::debug!(path = %path, "inbox: continuation advanced, cleaning up stored message");
                location_index.remove(storage_path);
                true
            } else {
                tracing::debug!(path = %path, "inbox: continuation not advanced, message stays");
                false
            }
        }
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "inbox: continuation advance failed");
            false
        }
    }
}

/// Check if an advancement result entity contains {advanced: true}.
fn check_advanced(entity: &Entity) -> bool {
    let val: ciborium::Value = match ciborium::from_reader(entity.data.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let map = match val.as_map() {
        Some(m) => m,
        None => return false,
    };
    for (k, v) in map {
        if k.as_text() == Some("advanced") {
            return v.as_bool() == Some(true);
        }
    }
    false
}

/// Extract result and status fields from an InboxDeliveryData entity's data.
/// Returns (result_bytes, status) or None if parsing fails.
fn extract_delivery_fields(data: &[u8]) -> Option<(Vec<u8>, u32)> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    let mut result_bytes = None;
    let mut status = STATUS_OK;
    for (k, v) in map {
        match k.as_text()? {
            "result" => {
                // result may be null (valid per spec), raw bytes, or any CBOR value
                if v.is_null() {
                    result_bytes = Some(vec![0xf6]); // CBOR null
                } else if let Some(b) = v.as_bytes() {
                    result_bytes = Some(b.to_vec());
                } else {
                    // Re-encode as CBOR bytes
                    let mut buf = Vec::new();
                    ciborium::into_writer(v, &mut buf).ok()?;
                    result_bytes = Some(buf);
                }
            }
            "status" => {
                if let Some(i) = v.as_integer() {
                    status = i128::from(i) as u32;
                }
            }
            _ => {}
        }
    }
    Some((result_bytes.unwrap_or_else(|| vec![0xf6]), status))
}

fn make_error_entity(code: &str, message: &str) -> Entity {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    // Canonical error type per ENTITY-NATIVE-TYPE-SYSTEM.
    Entity::new("system/protocol/error", data).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id() -> String {
        entity_crypto::Keypair::from_seed([42u8; 32]).peer_id().to_string()
    }

    fn make_inbox() -> InboxHandler {
        InboxHandler::new(
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
            test_peer_id(),
        )
    }

    fn make_test_execute(operation: &str, params_data: &[u8], resource_path: &str) -> Entity {
        // Per spec §3.4, params is an inline entity {content_hash, data, type}.
        let params_entity = Entity::new("system/inbox/receive-params", params_data.to_vec()).unwrap();
        let params_data_val: ciborium::Value =
            ciborium::from_reader(params_data).unwrap_or(ciborium::Value::Null);
        let params_inline = entity_ecf::Value::Map(vec![
            (entity_ecf::text("content_hash"), entity_ecf::Value::Bytes(params_entity.content_hash.to_bytes().to_vec())),
            (entity_ecf::text("data"), params_data_val),
            (entity_ecf::text("type"), entity_ecf::text("system/inbox/receive-params")),
        ]);
        let mut fields = vec![
            (entity_ecf::text("operation"), entity_ecf::text(operation)),
            (entity_ecf::text("params"), params_inline),
            (
                entity_ecf::text("request_id"),
                entity_ecf::text("test-req-1"),
            ),
            (
                entity_ecf::text("uri"),
                entity_ecf::text("system/inbox"),
            ),
        ];
        if !resource_path.is_empty() {
            fields.push((
                entity_ecf::text("resource"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("targets"),
                    entity_ecf::Value::Array(vec![entity_ecf::text(resource_path)]),
                )]),
            ));
        }
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        Entity::new(entity_types::TYPE_EXECUTE, data).unwrap()
    }

    fn make_ctx(_inbox: &InboxHandler, operation: &str, resource_path: &str) -> HandlerContext {
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("message"), entity_ecf::text("hello")),
        ]));
        let params = Entity::new("system/inbox/receive-params", params_data.clone()).unwrap();
        let execute = make_test_execute(operation, &params_data, resource_path);
        let resource_target = if resource_path.is_empty() {
            None
        } else {
            Some(entity_capability::ResourceTarget {
                targets: vec![resource_path.to_string()],
                exclude: vec![],
            })
        };
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            pattern: "system/inbox".to_string(),
            suffix: String::new(),
            resource_target,
            author: None,
            session_peer_id: None,
            request_id: "test-req-1".to_string(),
            operation: operation.to_string(),
            execute_fn: None,
            included: std::collections::HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        }
    }

    #[test]
    fn test_inbox_pattern() {
        let inbox = make_inbox();
        assert_eq!(inbox.pattern(), format!("/{}/system/inbox", test_peer_id()));
        assert_eq!(inbox.name(), "inbox");
        assert_eq!(inbox.operations(), &["receive"]);
    }

    #[tokio::test]
    async fn test_receive_stores_message() {
        let inbox = make_inbox();
        let ctx = make_ctx(&inbox, "receive", "user/messages");
        let result = inbox.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, "system/inbox/receive-result");

        // Verify the message was stored
        let entries = inbox.location_index.list("user/messages/");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].path.starts_with("user/messages/"));
    }

    #[tokio::test]
    async fn test_receive_no_resource_returns_400() {
        let inbox = make_inbox();
        let ctx = make_ctx(&inbox, "receive", "");
        let result = inbox.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_unknown_operation_returns_400() {
        let inbox = make_inbox();
        let ctx = make_ctx(&inbox, "delete", "user/messages");
        let result = inbox.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_receive_result_contains_path_and_hash() {
        let inbox = make_inbox();
        let ctx = make_ctx(&inbox, "receive", "inbox/test");
        let result = inbox.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let has_path = map.iter().any(|(k, _)| k.as_text() == Some("path"));
        let has_hash = map.iter().any(|(k, _)| k.as_text() == Some("content_hash"));
        assert!(has_path, "result should contain path");
        assert!(has_hash, "result should contain content_hash");
    }

    #[tokio::test]
    async fn test_receive_multiple_messages() {
        let inbox = make_inbox();

        // Send two messages with different request IDs
        let mut ctx1 = make_ctx(&inbox, "receive", "inbox/multi");
        ctx1.request_id = "req-1".to_string();
        inbox.handle(&ctx1).await.unwrap();

        let mut ctx2 = make_ctx(&inbox, "receive", "inbox/multi");
        ctx2.request_id = "req-2".to_string();
        inbox.handle(&ctx2).await.unwrap();

        let entries = inbox.location_index.list("inbox/multi/");
        assert_eq!(entries.len(), 2);
    }

    // --- InboxDeliveryData extraction tests ---

    #[test]
    fn test_extract_delivery_fields_basic() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("original_request_id"),
                entity_ecf::text("req-42"),
            ),
            (
                entity_ecf::text("result"),
                entity_ecf::Value::Bytes(vec![1, 2, 3]),
            ),
            (entity_ecf::text("status"), entity_ecf::integer(404)),
        ]));
        let (result, status) = extract_delivery_fields(&data).unwrap();
        assert_eq!(result, vec![1, 2, 3]);
        assert_eq!(status, 404);
    }

    #[test]
    fn test_extract_delivery_fields_null_result() {
        // Per spec: result may be null — that's valid
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("original_request_id"),
                entity_ecf::text("req-1"),
            ),
            (entity_ecf::text("result"), entity_ecf::Value::Null),
            (entity_ecf::text("status"), entity_ecf::integer(200)),
        ]));
        let (result, status) = extract_delivery_fields(&data).unwrap();
        assert_eq!(result, vec![0xf6]); // CBOR null
        assert_eq!(status, 200);
    }

    #[test]
    fn test_extract_delivery_fields_default_status() {
        // No status field → defaults to 200
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("original_request_id"),
                entity_ecf::text("req-1"),
            ),
            (
                entity_ecf::text("result"),
                entity_ecf::Value::Bytes(vec![42]),
            ),
        ]));
        let (result, status) = extract_delivery_fields(&data).unwrap();
        assert_eq!(result, vec![42]);
        assert_eq!(status, STATUS_OK);
    }

    #[test]
    fn test_extract_delivery_fields_cbor_value_result() {
        // result is a CBOR map (not raw bytes) — should be re-encoded
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("original_request_id"),
                entity_ecf::text("req-1"),
            ),
            (
                entity_ecf::text("result"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("key"),
                    entity_ecf::text("value"),
                )]),
            ),
            (entity_ecf::text("status"), entity_ecf::integer(200)),
        ]));
        let (result, status) = extract_delivery_fields(&data).unwrap();
        assert_eq!(status, 200);
        // Result should be valid CBOR
        let val: ciborium::Value = ciborium::from_reader(result.as_slice()).unwrap();
        assert!(val.as_map().is_some());
    }
}
