//! system/continuation handler — advance, resume, abandon.
//!
//! Implements forward continuations (§3.4) and join continuations (§3.5).
//! Supports suspend/resume/abandon for paused execution chains.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_entity::{Entity, EntityUri};
use entity_handler::{
    DeliverySpec, ExecuteFn, ExecuteOptions, Handler, HandlerContext, HandlerError, HandlerResult,
    STATUS_BAD_REQUEST, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OK,
};
use entity_hash::Hash;
use entity_store::{CasError, ContentStore, LocationIndex};

// ---------------------------------------------------------------------------
// Continuation engine error codes (EXTENSION-CONTINUATION v1.20 Appendix A).
// Canonical home for engine-emitted `code` values; same string is used for
// both `result.data.code` on emitted error descriptions AND the `{reason}`
// path segment on `lost`-variant chain-error markers (§3.10.5 single rule).
// ---------------------------------------------------------------------------

/// An `on_error` deliver-target dispatch failed (transient or permanent).
/// Per v1.9 §3.4 A.1. Maps to `status` 500 on emitted errors.
pub const CODE_ON_ERROR_DISPATCH_FAILED: &str = "on_error_dispatch_failed";
/// `result_merge: true` met a non-map post-transform value at chain assembly.
/// Per v1.16 §3.4. Maps to `status` 400.
pub const CODE_MERGE_VALUE_NOT_MAP: &str = "merge_value_not_map";
/// A continuation-transform vocabulary evaluation produced an error.
/// Per §2.2 transform contract. Maps to `status` 400.
#[allow(dead_code)]
pub const CODE_TRANSFORM_FAILED: &str = "transform_failed";
/// The continuation entity at install time was malformed. Per §3.2.
/// Maps to `status` 400.
#[allow(dead_code)]
pub const CODE_CHAIN_CONSTRUCTION_INVALID: &str = "chain_construction_invalid";

// ---------------------------------------------------------------------------
// Per-request transport error codes (V7 §6.12). Used as `{reason}` for lost
// markers when the failure is transport-level (no `EXECUTE_RESPONSE` was
// received). Discriminated from `HandlerError::Internal` error strings; see
// `classify_transport_failure` below.
// ---------------------------------------------------------------------------

const CODE_RECV_TIMEOUT: &str = "recv_timeout";
const CODE_CONNECTION_BROKEN: &str = "connection_broken";
const CODE_PROTOCOL_ERROR: &str = "protocol_error";

/// V7 §3.3 line 736 canonical 403 code (cap-rejection). Used by tests +
/// the cap-rejection-mirror flow (which currently sources the string via
/// `read_result_code`); kept as a named constant for canonical reference.
#[allow(dead_code)]
const CODE_CAPABILITY_DENIED: &str = "capability_denied";

/// Context for the EXTENSION-CONTINUATION §3.4 lost-error markers
/// (A.1 v1.10 and v1.13 / I-8). Threaded from `handle_advance` (which
/// has the `HandlerContext`) down to the dispatch sites so a failed
/// `on_error` delivery (A.1) or a no-`on_error` non-2xx (v1.13) can be
/// recorded as an observation. `chain_id` falls back to the request id
/// when bounds carry none, so the marker path is always well-formed.
///
/// `step_index` is the **original request ID** for BOTH cases per
/// CONTINUATION v1.9 (A.1) and v1.14 (v1.13 pin). The request ID is the
/// only stable key that makes idempotent re-binding under retry actually
/// idempotent — a flapping target overwrites its own marker rather than
/// accumulating markers under different keys. Pre-v1.14 Rust used
/// `cascade_depth` (not stable across the impl's internal book-keeping);
/// v1.14 absorption moves the field back to request_id.
#[derive(Debug, Clone)]
struct ChainErr {
    chain_id: String,
    #[allow(dead_code)]
    request_id: String,
    step_index: String,
}

/// The continuation handler: system/continuation with advance, resume, abandon.
pub struct ContinuationHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    /// Per-join-path mutex for serializing concurrent slot arrivals.
    join_locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    qualified_pattern: String,
    /// Retained for API stability and constructor signature.
    /// Path resolution now flows from peer-qualified resource targets;
    /// PROPOSAL-PATH-AS-RESOURCE-HYGIENE removed the install-time `path`
    /// param that previously needed local-peer-id qualification.
    #[allow(dead_code)]
    local_peer_id: String,
}

/// Path-safety sanitizer per EXTENSION-CONTINUATION v1.19 §3.10.5 (V7 §1.4
/// path-segment rules). Code strings emitted by canonical homes are already
/// path-safe; this guards against non-conformant handler-emitted codes
/// reaching the path concat. Returns `unspecified_error` for any code that
/// contains characters invalid in a single path segment.
fn sanitize_reason_segment(reason: &str) -> String {
    if reason.is_empty() {
        return "unspecified_error".to_string();
    }
    for b in reason.bytes() {
        // V7 §1.4: no null byte, no embedded `/`, no whitespace, ASCII printable.
        if b == 0 || b == b'/' || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            return "unspecified_error".to_string();
        }
        if b < 0x20 || b == 0x7f {
            return "unspecified_error".to_string();
        }
    }
    reason.to_string()
}

/// Best-effort extract the target peer ID (base58) from an absolute URI of
/// the form `entity://{peer_id}/...` or `/{peer_id}/...`. Used to populate
/// `target_peer_id` per §3.10.6. Returns `None` for handler-relative URIs.
fn peer_id_from_uri(uri: &str) -> Option<String> {
    if let Some(rest) = uri.strip_prefix("entity://") {
        if let Some(slash) = rest.find('/') {
            return Some(rest[..slash].to_string());
        }
        return Some(rest.to_string());
    }
    if let Some(rest) = uri.strip_prefix('/') {
        if let Some(slash) = rest.find('/') {
            return Some(rest[..slash].to_string());
        }
        return Some(rest.to_string());
    }
    None
}

/// Read `result.data.code` from an emitted error response's result-entity
/// data. Pre-v1.19 helper retained as `error_code_from_result` below for
/// the existing flows; this is the explicit-string accessor used by the
/// v1.19 §3.10.5 `{reason}` = `result.data.code` rule.
fn read_result_code(result_data: &[u8]) -> Option<String> {
    let v: ciborium::Value = ciborium::from_reader(result_data).ok()?;
    let map = v.as_map()?;
    for (k, val) in map {
        if k.as_text() == Some("code") {
            return val.as_text().map(|s| s.to_string());
        }
    }
    None
}

/// Classify a `HandlerError::Internal`-shaped dispatch failure into one of
/// the V7 §6.12 per-request transport codes. The remote-dispatch path
/// (`core/peer/src/remote.rs::send_execute`) returns
/// `PeerError::ConnectionError(...)` for transport-layer failures, which
/// gets flattened to `HandlerError::Internal(format!("remote execute to
/// {}: {}", ...))` in `core/peer/src/connection.rs`. Without restructuring
/// HandlerError to carry typed transport variants, we string-match here
/// to discriminate. Pattern strings track the exact messages emitted by
/// `send_execute` post-Class-G rework.
fn classify_transport_failure(err_text: &str) -> &'static str {
    let lower = err_text.to_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        CODE_RECV_TIMEOUT
    } else if lower.contains("reader task terminated")
        || lower.contains("connection")
        || lower.contains("broken pipe")
        || lower.contains("eof")
    {
        CODE_CONNECTION_BROKEN
    } else if lower.contains("decode") || lower.contains("parse") || lower.contains("malformed") {
        CODE_PROTOCOL_ERROR
    } else {
        // Unknown transport-layer shape — surface as protocol_error per
        // V7 §6.12 (the "consumer has no other code to record" fallback).
        CODE_PROTOCOL_ERROR
    }
}

/// Capture failure-origination timestamp in Unix milliseconds, per
/// EXTENSION-CONTINUATION v1.20 §3.10.6 timestamp-capture discipline.
/// Call this at the failure site, not at marker-bind time.
fn capture_failure_timestamp_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl ContinuationHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/continuation", local_peer_id);
        Self {
            content_store,
            location_index,
            join_locks: tokio::sync::Mutex::new(HashMap::new()),
            qualified_pattern,
            local_peer_id,
        }
    }

    async fn get_join_lock(&self, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.join_locks.lock().await;
        locks
            .entry(path.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for ContinuationHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "install" => self.handle_install(ctx).await,
            "advance" => self.handle_advance(ctx).await,
            "resume" => self.handle_resume(ctx).await,
            "abandon" => self.handle_abandon(ctx).await,
            _ => Ok(error_result(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown: {}", ctx.operation),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "continuations"
    }

    fn operations(&self) -> &[&str] {
        &["install", "advance", "resume", "abandon"]
    }
}

// ---------------------------------------------------------------------------
// Advance operation
// ---------------------------------------------------------------------------

impl ContinuationHandler {
    async fn handle_advance(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let path = match ctx.resource_target.as_ref().and_then(|r| r.targets.first()) {
            Some(p) if !p.is_empty() => p.clone(),
            _ => {
                tracing::debug!(request_id = %ctx.request_id, "continuation advance: missing resource target");
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "resource target path required",
                ));
            }
        };

        tracing::debug!(request_id = %ctx.request_id, path = %path, "continuation advance");

        // Decode advance request: {result: bytes, status: optional uint}
        let (result_bytes, status) = decode_advance_request(&ctx.params.data)?;
        let status = status.unwrap_or(STATUS_OK);

        let execute_fn = ctx
            .execute_fn
            .as_ref()
            .ok_or_else(|| HandlerError::Internal("execute_fn not available".into()))?;

        // §3.4 lost-error marker context (A.1 v1.10 + v1.13 / I-8).
        // `chain_id` falls back to request_id so the marker path is
        // always well-formed. `step_index` is the original request ID
        // for both cases (A.1 v1.9 + v1.13 v1.14 pin) — using the
        // request id as the key makes idempotent re-binding under retry
        // actually idempotent.
        let chain_err = ChainErr {
            chain_id: ctx
                .bounds
                .as_ref()
                .and_then(|b| b.chain_id.clone())
                .unwrap_or_else(|| ctx.request_id.clone()),
            request_id: ctx.request_id.clone(),
            step_index: ctx.request_id.clone(),
        };

        let result = self
            .advance_at_path(
                execute_fn,
                &path,
                &result_bytes,
                status,
                &chain_err,
                &ctx.included,
            )
            .await;
        match &result {
            Ok(r) => tracing::debug!(
                request_id = %ctx.request_id,
                path = %path,
                status = r.status,
                "continuation advance: completed"
            ),
            Err(e) => tracing::debug!(
                request_id = %ctx.request_id,
                path = %path,
                error = %e,
                "continuation advance: error"
            ),
        }
        result
    }

    async fn advance_at_path(
        &self,
        execute_fn: &ExecuteFn,
        path: &str,
        result_bytes: &[u8],
        status: u32,
        chain_err: &ChainErr,
        included: &HashMap<Hash, Entity>,
    ) -> Result<HandlerResult, HandlerError> {
        // Read entity at path
        if let Some(hash) = self.location_index.get(path) {
            if let Some(entity) = self.content_store.get(&hash) {
                match entity.entity_type.as_str() {
                    "system/continuation" => {
                        return self
                            .advance_forward(
                                execute_fn,
                                path,
                                &entity,
                                result_bytes,
                                status,
                                chain_err,
                                included,
                            )
                            .await;
                    }
                    "system/continuation/join" => {
                        return Ok(error_result(
                            STATUS_BAD_REQUEST,
                            "join_requires_slot_path",
                            "join continuations must be advanced via slot sub-path",
                        ));
                    }
                    _ => {} // fall through
                }
            }
        }

        // Check parent for join
        if let Some(slash_idx) = path.rfind('/') {
            let parent = &path[..slash_idx];
            let slot = &path[slash_idx + 1..];
            if let Some(parent_hash) = self.location_index.get(parent) {
                if let Some(parent_entity) = self.content_store.get(&parent_hash) {
                    if parent_entity.entity_type == "system/continuation/join" {
                        return self
                            .advance_join_slot(
                                execute_fn,
                                parent,
                                slot,
                                &parent_entity,
                                result_bytes,
                                chain_err,
                            )
                            .await;
                    }
                }
            }
        }

        // Nothing found
        Ok(advancement_not_found())
    }

    /// EXTENSION-CONTINUATION §3.4: bind an informational lost-error
    /// marker. Two `reason` values:
    /// - `"on_error_dispatch_failed"` (A.1, v1.10): an `on_error` dispatch
    ///   itself failed.
    /// Bind a `lost`-variant chain-error marker per EXTENSION-CONTINUATION
    /// v1.20 §3.10. Sender / originator side; chain dispatch was attempted
    /// but its outcome was not delivered back to the chain step.
    ///
    /// **`{reason}` value (v1.19 §3.10.5 single rule):** `{reason}` IS the
    /// `code` field of the failure description verbatim. Caller selects the
    /// code from the appropriate canonical home:
    /// - **Engine-internal failure** — EXTENSION-CONTINUATION Appendix A
    ///   (`CODE_ON_ERROR_DISPATCH_FAILED`, `CODE_MERGE_VALUE_NOT_MAP`, …)
    /// - **Response-derived failure** (downstream non-2xx) — `result.data.code`
    ///   from the response (e.g. `capability_denied` for 403, handler codes)
    /// - **Transport-level failure** (no response) — V7 §6.12
    ///   (`recv_timeout`, `connection_broken`, `protocol_error`)
    ///
    /// **Path scheme (v1.20 §3.10.1):**
    /// `/{local_peer_id}/system/runtime/chain-errors/lost/{chain_id}/{step_index}/{reason}/{marker_hash_hex}`
    /// where `{marker_hash_hex}` is the marker entity's own content hash in
    /// V7 §3.5 invariant-pointer hex form (66 chars, `00`-prefixed for ECFv1).
    /// Each distinct occurrence lands at its own path; the tree IS the event
    /// log. Redelivery dedupes naturally because the body's `timestamp`
    /// (captured at failure-origination per v1.20 §3.10.6) is identical on
    /// redelivery.
    ///
    /// **Timestamp-capture discipline (v1.20 §3.10.6):** the caller MUST
    /// pass `timestamp_ms` captured at failure-origination (when the failure
    /// was observed), NOT regenerated at this bind site. Same value across
    /// retries / redeliveries of the same logical event → bytes-identical
    /// body → genuine `tree:put` no-op. Re-occurrences (10 separate flaps)
    /// get distinct timestamps → distinct `content_hash` → 10 distinct paths.
    ///
    /// **Path safety (v1.19 §3.10.5):** `{reason}` is sanitized via
    /// `sanitize_reason_segment`; non-path-safe codes fall back to
    /// `unspecified_error` with the original code preserved in the body.
    ///
    /// **Mirror pointer (v1.20 §3.10.4):** when this lost marker mirrors a
    /// peer's `rejected` marker (the dispatched EXECUTE came back as a 403
    /// carrying `ErrorData.rejected_marker`), pass `rejected_marker_hash` so
    /// the body carries the cross-peer audit reference.
    ///
    /// **Observation sink only** — MUST NOT trigger advancement, retry, or
    /// any reactive behavior. Bind failure logs `tracing::warn!` per
    /// §3.10.8 visibility convention.
    fn write_lost_error_marker(
        &self,
        ce: &ChainErr,
        failed_uri: &str,
        original_status: u32,
        reason: &str,
        timestamp_ms: u64,
        rejected_marker_hash: Option<Hash>,
    ) {
        let safe_reason = sanitize_reason_segment(reason);
        // §3.10.6 body fields. Reserved-across-both-kinds: reason, timestamp,
        // chain_id, step_index. Reserved on `lost`: target_uri (was
        // `failed_uri` in pre-v1.20 Rust), target_peer_id (best-effort
        // derived below), status (was `original_status`). Mirror body field
        // (when present): `rejected_marker_hash`.
        let target_peer_id = peer_id_from_uri(failed_uri).unwrap_or_default();
        let mut body_fields = vec![
            (entity_ecf::text("chain_id"), entity_ecf::text(&ce.chain_id)),
            (entity_ecf::text("code"), entity_ecf::text(reason)),
            (entity_ecf::text("reason"), entity_ecf::text(&safe_reason)),
            (
                entity_ecf::text("status"),
                entity_ecf::integer(original_status as i64),
            ),
            (
                entity_ecf::text("step_index"),
                entity_ecf::text(&ce.step_index),
            ),
            (entity_ecf::text("target_peer_id"), entity_ecf::text(&target_peer_id)),
            (entity_ecf::text("target_uri"), entity_ecf::text(failed_uri)),
            (
                entity_ecf::text("timestamp"),
                entity_ecf::integer(timestamp_ms as i64),
            ),
        ];
        if let Some(h) = rejected_marker_hash {
            body_fields.push((
                entity_ecf::text("rejected_marker_hash"),
                entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
            ));
        }
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(body_fields));
        let entity = match Entity::new("system/runtime/chain-error-lost", data) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    chain_id = %ce.chain_id,
                    step_index = %ce.step_index,
                    reason = %safe_reason,
                    error = %e,
                    "F11/§3.10.8: lost-error marker entity build FAILED",
                );
                return;
            }
        };
        // §3.10.1 path scheme: terminal `{marker_hash_hex}` segment in V7
        // §3.5 invariant-pointer hex form (Hash::to_hex — 66 chars,
        // `00`-prefixed for ECFv1-SHA-256).
        let marker_path = format!(
            "/{}/system/runtime/chain-errors/lost/{}/{}/{}/{}",
            self.local_peer_id,
            ce.chain_id,
            ce.step_index,
            safe_reason,
            entity.content_hash.to_hex(),
        );
        match self.content_store.put(entity) {
            Ok(h) => {
                self.location_index.set(&marker_path, h);
            }
            Err(e) => {
                tracing::warn!(
                    path = %marker_path,
                    error = %e,
                    "F11/§3.10.8: lost-error marker bind FAILED",
                );
            }
        }
    }

    async fn advance_forward(
        &self,
        execute_fn: &ExecuteFn,
        path: &str,
        cont_entity: &Entity,
        result_bytes: &[u8],
        status: u32,
        chain_err: &ChainErr,
        included: &HashMap<Hash, Entity>,
    ) -> Result<HandlerResult, HandlerError> {
        let cont = decode_continuation(cont_entity)?;

        // Error path: if status >= 400 and on_error is set. Per
        // CONTINUATION §3.5, `on_error` is a `system/delivery-spec`;
        // dispatch target = spec.uri, operation = spec.operation. The
        // on_error URI is the sink path — sink handlers (typically
        // `system/inbox/...`) require a `resource` to write to. Pass
        // the on_error URI as the explicit resource so the sink handler
        // stores the error payload at that path. Without this, the
        // child invocation inherits no resource and the sink rejects
        // with 400 `invalid_params` (CROSS-IMPL onerror_routed WARN —
        // entries did not land at the sink).
        if status >= 400 {
            if let Some(on_error) = &cont.on_error {
                let params_entity = Entity::new("primitive/any", result_bytes.to_vec())
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                let dispatch_cap =
                    self.resolve_dispatch_capability(&cont.dispatch_capability);
                let sink_resource = entity_capability::ResourceTarget {
                    targets: vec![on_error.uri.clone()],
                    exclude: Vec::new(),
                };
                let opts = ExecuteOptions {
                    resource: Some(sink_resource),
                    capability: dispatch_cap,
                    ..Default::default()
                };
                let oe_result = execute_fn(
                    on_error.uri.clone(),
                    on_error.operation.clone(),
                    params_entity,
                    opts,
                )
                .await;
                // §3.4 A.1: on_error is best-effort (its result is not
                // propagated). If the compensation delivery itself failed,
                // record an observation marker — no control-flow change.
                let oe_failed = match &oe_result {
                    Err(_) => true,
                    Ok(r) => r.status >= 400,
                };
                if oe_failed {
                    // v1.19 Appendix A engine code. v1.20 §3.10.6 timestamp
                    // captured at failure-origination (here — the on_error
                    // delivery itself failed).
                    let ts = capture_failure_timestamp_ms();
                    self.write_lost_error_marker(
                        chain_err,
                        &on_error.uri,
                        status,
                        CODE_ON_ERROR_DISPATCH_FAILED,
                        ts,
                        None,
                    );
                }
                self.handle_remaining_executions(path)?;
                return Ok(advancement_result(true));
            }
        }

        // Normal path: transform + assemble + dispatch.
        // `transformed` is the post-extract/select/transform_ops value —
        // the single value BOTH dispatch-mode params assembly and the
        // `*_extract` EXECUTE-field resolution operate on (§2.2, §3.6).
        let transformed = apply_transform(result_bytes, &cont.result_transform, included)?;
        // EXTENSION-CONTINUATION v1.16 §3.6 Step 2: Merge dispatch-mode.
        // When `result_merge` is true, shallow-union the post-transform map
        // value into static `params` (result keys win on collision). A
        // non-map value degrades to static-only params and binds a
        // `merge_value_not_map` lost-error marker (§3.4).
        let (dispatch_params, merge_degraded) = if cont.result_merge {
            assemble_params_merge(&cont.params, &transformed)?
        } else {
            (
                assemble_params(&cont.params, &cont.result_field, &transformed)?,
                false,
            )
        };
        if merge_degraded {
            // v1.19 Appendix A engine code; v1.20 §3.10.6 timestamp captured
            // at failure-origination (here — the merge degraded at assembly).
            let ts = capture_failure_timestamp_ms();
            self.write_lost_error_marker(
                chain_err,
                &cont.target,
                400,
                CODE_MERGE_VALUE_NOT_MAP,
                ts,
                None,
            );
        }

        let params_entity = Entity::new("primitive/any", dispatch_params)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // §3.6 step 3: resolve dynamic EXECUTE fields from the transform,
        // falling back to the static values on the continuation entity.
        // The navigated value is the post-pipeline value (best-effort: a
        // non-map / decode failure leaves every field at its static
        // default via resolve_or_default).
        let post_value: ciborium::Value =
            ciborium::from_reader(transformed.as_slice()).unwrap_or(ciborium::Value::Null);
        let (target_x, operation_x, resource_x) = match &cont.result_transform {
            Some(t) => (
                t.target_extract.clone(),
                t.operation_extract.clone(),
                t.resource_extract.clone(),
            ),
            None => (None, None, None),
        };
        let dispatch_target = resolve_or_default(&post_value, &target_x, &cont.target);
        let dispatch_operation =
            resolve_or_default(&post_value, &operation_x, &cont.operation);
        let dispatch_resource =
            resolve_or_default_resource(&post_value, &resource_x, &cont.resource);

        // W9: dispatch_capability is required for dispatching continuations.
        // The continuation handler's own grant is only for managing continuation
        // entities — it MUST NOT be used as fallback dispatch authority.
        let dispatch_cap = match self.resolve_dispatch_capability(&cont.dispatch_capability) {
            Some(cap) => Some(cap),
            None => {
                tracing::warn!(
                    path = %path,
                    target = %cont.target,
                    "continuation: missing dispatch_capability, cannot dispatch"
                );
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "missing_dispatch_capability",
                    "continuation must have dispatch_capability to dispatch",
                ));
            }
        };

        let opts = ExecuteOptions {
            resource: dispatch_resource,
            capability: dispatch_cap,
            deliver_to: cont.deliver_to.clone(),
            request_id: None,
            bounds: None,
            included: Vec::new(),
        };

        tracing::debug!(
            path = %path,
            target = %dispatch_target,
            operation = %dispatch_operation,
            static_target = %cont.target,
            result_field = ?cont.result_field,
            has_deliver_to = cont.deliver_to.is_some(),
            "continuation: dispatching to target"
        );

        match execute_fn(
            dispatch_target.clone(),
            dispatch_operation.clone(),
            params_entity,
            opts,
        )
        .await
        {
            Ok(result) => {
                tracing::debug!(
                    path = %path,
                    target = %dispatch_target,
                    status = result.status,
                    "continuation: dispatch completed"
                );
                // EXTENSION-CONTINUATION §3.10.2 v1.19 (lost variant,
                // response-derived failure): no-`on_error` forward dispatch
                // non-2xx records a lost-error marker. `{reason}` is
                // `result.data.code` verbatim (v1.19 §3.10.5 single rule —
                // replaces v1.18 invented `forward_dispatch_non2xx`).
                // Cap-rejection mirror (v1.20 §3.10.4): if the response
                // carries `ErrorData.rejected_marker`, body field
                // `rejected_marker_hash` mirrors the receiver-side marker.
                if result.status >= 400 && cont.on_error.is_none() {
                    let reason = read_result_code(&result.result.data)
                        .unwrap_or_else(|| CODE_PROTOCOL_ERROR.to_string());
                    let mirror = entity_protocol::extract_rejected_marker(&result.result);
                    let ts = capture_failure_timestamp_ms();
                    self.write_lost_error_marker(
                        chain_err,
                        &dispatch_target,
                        result.status,
                        &reason,
                        ts,
                        mirror,
                    );
                }
                self.handle_remaining_executions(path)?;
                Ok(advancement_result(true))
            }
            Err(e) => {
                // EXTENSION-CONTINUATION v1.10 §3.4 + v1.17 §2.2: forward
                // dispatch is fire-and-forget — a delivered EXECUTE that the
                // target handler rejects is a COMPLETED forward dispatch, not
                // a propagated Err. The handler's validation error reaches us
                // here as Err(HandlerError) (rather than Ok(error_result(...)))
                // because some receivers signal handler-level errors via the
                // typed-error channel; the two surfaces are semantically the
                // same: "delivered, handler signaled non-2xx". Convert to the
                // completed-dispatch shape so advance returns 200 and the
                // §2.2 best-effort totality is preserved (notably for
                // `deref_included` misses whose unresolved bytes downstream
                // handlers will reject — exactly the
                // `deref_included_miss_noop` cross-impl validator gate).
                //
                // True delivery/processing failures (network errors, transport
                // panics, etc.) are not currently distinguished from
                // handler-level Errs at this layer. If that becomes load-
                // bearing, factor the dispatch-failure classification through
                // a typed channel rather than reading magic into HandlerError
                // variants here.
                tracing::debug!(
                    path = %path,
                    target = %dispatch_target,
                    error = %e,
                    "continuation: dispatched handler returned Err; treating as completed forward dispatch (v1.10 §3.4)"
                );
                // §3.10.2 v1.19 transport-level failure: `{reason}` is from
                // V7 §6.12. HandlerError variants don't carry typed transport
                // info, so we classify Internal by string-match; InvalidParams
                // and NotSupported remain as handler-side codes (delivered
                // EXECUTE that the receiver rejected for shape reasons).
                let reason: &str = match &e {
                    HandlerError::InvalidParams(_) => "invalid_params",
                    HandlerError::NotSupported(_) => "not_supported",
                    HandlerError::Internal(s) => classify_transport_failure(s),
                };
                if cont.on_error.is_none() {
                    let ts = capture_failure_timestamp_ms();
                    self.write_lost_error_marker(
                        chain_err,
                        &dispatch_target,
                        400,
                        reason,
                        ts,
                        None,
                    );
                }
                self.handle_remaining_executions(path)?;
                Ok(advancement_result(true))
            }
        }
    }

    async fn advance_join_slot(
        &self,
        execute_fn: &ExecuteFn,
        parent_path: &str,
        slot_name: &str,
        _join_entity: &Entity,
        result_bytes: &[u8],
        chain_err: &ChainErr,
    ) -> Result<HandlerResult, HandlerError> {
        // Acquire per-path lock
        let lock = self.get_join_lock(parent_path).await;
        let _guard = lock.lock().await;

        // Re-read join entity under lock
        let join_hash = self
            .location_index
            .get(parent_path)
            .ok_or_else(|| HandlerError::Internal("join entity disappeared".into()))?;
        let join_entity = self
            .content_store
            .get(&join_hash)
            .ok_or_else(|| HandlerError::Internal("join entity not in store".into()))?;
        let join = decode_join(&join_entity)?;

        // Validate slot is expected
        if !join.expected.contains(&slot_name.to_string()) {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "unexpected_slot",
                &format!("slot '{}' not in expected list", slot_name),
            ));
        }

        // Accumulate result
        let mut received = join.received.clone();
        received.insert(slot_name.to_string(), result_bytes.to_vec());

        // Check if all slots are filled
        let remaining: Vec<String> = join
            .expected
            .iter()
            .filter(|e| !received.contains_key(*e))
            .cloned()
            .collect();

        if remaining.is_empty() {
            // All slots received — aggregate and dispatch
            let aggregated = encode_received_map(&received);

            // Build continuation data from join's dispatch fields
            let cont = ContinuationData {
                target: join.target.clone(),
                operation: join.operation.clone(),
                resource: join.resource.clone(),
                params: join.params.clone(),
                result_field: join.result_field.clone(),
                result_merge: false,
                result_transform: None,
                on_error: join.on_error.clone(),
                deliver_to: join.deliver_to.clone(),
                remaining_executions: join.remaining_executions,
                dispatch_capability: join.dispatch_capability,
            };

            let params = assemble_params(&cont.params, &cont.result_field, &aggregated)?;
            let params_entity = Entity::new("primitive/any", params)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;

            // W9: dispatch_capability required for join dispatch
            let dispatch_cap = match self.resolve_dispatch_capability(&cont.dispatch_capability) {
                Some(cap) => Some(cap),
                None => {
                    tracing::warn!(
                        parent_path = %parent_path,
                        target = %cont.target,
                        "continuation join: missing dispatch_capability, cannot dispatch"
                    );
                    return Ok(advancement_result(false));
                }
            };

            let opts = ExecuteOptions {
                resource: cont.resource.clone(),
                capability: dispatch_cap,
                deliver_to: cont.deliver_to.clone(),
                request_id: None,
                bounds: None,
                included: Vec::new(),
            };

            match execute_fn(
                cont.target.clone(),
                cont.operation.clone(),
                params_entity,
                opts,
            )
            .await
            {
                Ok(_) => {
                    // Handle lifecycle
                    match join.remaining_executions {
                        Some(n) if n <= 1 => {
                            // Delete the join
                            self.location_index.remove(parent_path);
                            self.content_store.remove(&join_hash);
                        }
                        Some(n) => {
                            // Decrement and reset received
                            let updated = JoinData {
                                remaining_executions: Some(n - 1),
                                received: HashMap::new(),
                                ..join
                            };
                            self.store_join(parent_path, &updated)?;
                        }
                        None => {
                            // Standing join: reset received for next round
                            let updated = JoinData {
                                received: HashMap::new(),
                                ..join
                            };
                            self.store_join(parent_path, &updated)?;
                        }
                    }
                    Ok(advancement_result(true))
                }
                Err(e) => {
                    // Check on_error before propagating. Per CONTINUATION
                    // §3.5: on_error is a delivery-spec; target = uri,
                    // operation = spec.operation. Pass the URI as resource
                    // so the sink handler (typically inbox) writes the
                    // error payload at the sink path — see the sibling
                    // forward-path fix for rationale.
                    if let Some(on_error) = &cont.on_error {
                        let error_params = Entity::new("primitive/any", aggregated.clone())
                            .map_err(|e| HandlerError::Internal(e.to_string()))?;
                        let dispatch_cap =
                            self.resolve_dispatch_capability(&cont.dispatch_capability);
                        let sink_resource = entity_capability::ResourceTarget {
                            targets: vec![on_error.uri.clone()],
                            exclude: Vec::new(),
                        };
                        let error_opts = ExecuteOptions {
                            resource: Some(sink_resource),
                            capability: dispatch_cap,
                            ..Default::default()
                        };
                        let oe_result = execute_fn(
                            on_error.uri.clone(),
                            on_error.operation.clone(),
                            error_params,
                            error_opts,
                        )
                        .await;
                        // §3.4 A.1: best-effort compensation. If the
                        // on_error delivery itself failed, record an
                        // observation marker — no control-flow change.
                        let oe_failed = match &oe_result {
                            Err(_) => true,
                            Ok(r) => r.status >= 400,
                        };
                        if oe_failed {
                            // v1.19 Appendix A engine code. v1.20 §3.10.6
                            // timestamp captured at failure-origination.
                            let ts = capture_failure_timestamp_ms();
                            self.write_lost_error_marker(
                                chain_err,
                                &on_error.uri,
                                500,
                                CODE_ON_ERROR_DISPATCH_FAILED,
                                ts,
                                None,
                            );
                        }
                        // Handle lifecycle
                        match join.remaining_executions {
                            Some(n) if n <= 1 => {
                                self.location_index.remove(parent_path);
                                self.content_store.remove(&join_hash);
                            }
                            Some(n) => {
                                let updated = JoinData {
                                    remaining_executions: Some(n - 1),
                                    received: HashMap::new(),
                                    ..join
                                };
                                self.store_join(parent_path, &updated)?;
                            }
                            None => {
                                let updated = JoinData {
                                    received: HashMap::new(),
                                    ..join
                                };
                                self.store_join(parent_path, &updated)?;
                            }
                        }
                        Ok(advancement_result(true))
                    } else {
                        Err(e)
                    }
                }
            }
        } else {
            // Not all slots: update join with accumulated received
            let updated = JoinData {
                received,
                ..join
            };
            self.store_join(parent_path, &updated)?;

            // Return partial result
            let remaining_arr: Vec<entity_ecf::Value> =
                remaining.iter().map(entity_ecf::text).collect();
            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("slot"), entity_ecf::text(slot_name)),
                (
                    entity_ecf::text("remaining"),
                    entity_ecf::Value::Array(remaining_arr),
                ),
            ]));
            let result = Entity::new("system/continuation/join-slot-result", data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            Ok(HandlerResult {
                status: STATUS_OK,
                result,
            included: std::collections::HashMap::new(),
            })
        }
    }

    /// Decrement `remaining_executions` (or delete if last) via a CAS retry
    /// loop. EXTENSION-CONTINUATION §3.3 requires CAS on this decrement so
    /// concurrent advancers cannot double-decrement or double-delete.
    fn handle_remaining_executions(&self, path: &str) -> Result<(), HandlerError> {
        loop {
            let current_hash = match self.location_index.get(path) {
                Some(h) => h,
                None => return Ok(()), // Already deleted concurrently.
            };
            let entity = match self.content_store.get(&current_hash) {
                Some(e) => e,
                None => return Ok(()), // Stale pointer; nothing to update.
            };
            let cont = decode_continuation(&entity)?;

            match cont.remaining_executions {
                Some(n) if n <= 1 => {
                    match self.location_index.compare_and_remove(path, current_hash) {
                        Ok(_) => {
                            self.content_store.remove(&current_hash);
                            return Ok(());
                        }
                        Err(CasError::NotFound) => return Ok(()),
                        Err(CasError::Mismatch(_)) => continue,
                    }
                }
                Some(n) => {
                    let updated = ContinuationData {
                        remaining_executions: Some(n - 1),
                        ..cont
                    };
                    let data = encode_continuation(&updated);
                    let new_entity = Entity::new("system/continuation", data)
                        .map_err(|e| HandlerError::Internal(e.to_string()))?;
                    let new_hash = self
                        .content_store
                        .put(new_entity)
                        .map_err(|e| HandlerError::Internal(e.to_string()))?;
                    match self
                        .location_index
                        .compare_and_swap(path, current_hash, new_hash)
                    {
                        Ok(()) => return Ok(()),
                        Err(CasError::NotFound) => return Ok(()),
                        Err(CasError::Mismatch(_)) => continue,
                    }
                }
                None => return Ok(()),
            }
        }
    }

    fn store_join(&self, path: &str, join: &JoinData) -> Result<(), HandlerError> {
        let data = encode_join(join);
        let entity = Entity::new("system/continuation/join", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let hash = self
            .content_store
            .put(entity)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        self.location_index.set(path, hash);
        Ok(())
    }

    fn resolve_dispatch_capability(&self, cap_hash: &Option<Hash>) -> Option<Entity> {
        let hash = (*cap_hash)?;
        self.content_store.get(&hash)
    }
}

// ---------------------------------------------------------------------------
// Install operation
// (PROPOSAL-COHERENT-CAPABILITY-AUTHORITY CT1-CT3, EXTENSION-CONTINUATION §3.2)
// ---------------------------------------------------------------------------

impl ContinuationHandler {
    /// Install a forward or join continuation entity at `path`.
    ///
    /// This is the proper create path for `system/continuation` and
    /// `system/continuation/join` entities (CT1). The handler:
    ///
    /// 1. Validates the install request fields (incl. fail-closed rejection
    ///    of an unrecognized `transform_ops` op, §2.2 / §8.1 G1).
    /// 2. Performs the §3.1a **in-chain** authorization check on
    ///    `dispatch_capability` via `check_creator_authority` (V7 §5.5) —
    ///    the EXECUTE author MUST appear as a granter *anywhere in* the
    ///    cap's authority chain (CT2). NOT a chain-*root* check: a root
    ///    check is correct only for the local case and breaks every
    ///    cross-peer continuation (§3.1a, §4.2 case 3). Closes the
    ///    "Finding 3" exploit where an actor with `tree:put` on the
    ///    continuation namespace embeds an arbitrary capability and
    ///    triggers advance to wield it.
    /// 3. Constructs the continuation entity (forward or join).
    /// 4. Persists it under the handler's own grant.
    async fn handle_install(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // Path-as-resource (PROPOSAL-PATH-AS-RESOURCE-HYGIENE §3.2,
        // P-CONTINUATION-1): `system/continuation/install-request` is
        // eliminated. Caller passes a continuation entity directly as params;
        // the install path is carried in resource. Forward-vs-join is
        // discriminated by `params.type`.
        let qualified_path = match ctx.resource_target.as_ref() {
            Some(rt) if rt.targets.len() == 1 && rt.exclude.is_empty() => rt.targets[0].clone(),
            _ => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "ambiguous_resource",
                    "install requires exactly one resource target (the suspended continuation path)",
                ));
            }
        };

        // Discriminate by entity type. Both forward and join are accepted by
        // the same `install` op (proposal §3.2: definitive — one op, two types).
        let kind = match ctx.params.entity_type.as_str() {
            entity_types::TYPE_CONTINUATION => "forward",
            entity_types::TYPE_CONTINUATION_JOIN => "join",
            other => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    &format!(
                        "install expects system/continuation or system/continuation/join in params, got {}",
                        other
                    ),
                ));
            }
        };

        // Validate the continuation entity's required fields and extract the
        // embedded dispatch_capability hash for R1.
        let dispatch_cap = match kind {
            "forward" => {
                let data = decode_continuation(&ctx.params)?;
                if data.target.is_empty() || data.operation.is_empty() {
                    return Ok(error_result(
                        STATUS_BAD_REQUEST,
                        "invalid_params",
                        "continuation target and operation are required",
                    ));
                }
                // §2.2 / §8.1 G1: an unrecognized transform_ops `op` MUST be
                // rejected at install — fail-closed, never silently skipped.
                // v1.15: `collect_keys` with both `field` and `fields` rejects
                // with `400 invalid_transform_args` (op recognized, args invalid).
                if let Err(e) = validate_transform_ops(&data.result_transform) {
                    return Ok(match e {
                        TransformOpsError::UnknownOp(bad_op) => error_result(
                            STATUS_BAD_REQUEST,
                            "unknown_transform_op",
                            &format!(
                                "transform_ops contains unrecognized op '{}' (fail-closed per EXTENSION-CONTINUATION §2.2)",
                                bad_op
                            ),
                        ),
                        TransformOpsError::InvalidArgs(msg) => error_result(
                            STATUS_BAD_REQUEST,
                            "invalid_transform_args",
                            &msg,
                        ),
                    });
                }
                // EXTENSION-CONTINUATION v1.16 §3.2: `result_merge` and
                // `result_field` are mutually exclusive — both express
                // "what to do with the transformed value" and combining is
                // ambiguous. Reject at install with 400 invalid_continuation.
                if data.result_merge && data.result_field.is_some() {
                    return Ok(error_result(
                        STATUS_BAD_REQUEST,
                        "invalid_continuation",
                        "result_merge and result_field are mutually exclusive (EXTENSION-CONTINUATION v1.16 §3.2)",
                    ));
                }
                match data.dispatch_capability {
                    Some(h) => h,
                    None => {
                        return Ok(error_result(
                            STATUS_BAD_REQUEST,
                            "missing_dispatch_capability",
                            "install requires dispatch_capability for the deferred dispatch",
                        ));
                    }
                }
            }
            _ /* join */ => {
                let data = decode_join(&ctx.params)?;
                if data.target.is_empty() || data.operation.is_empty() {
                    return Ok(error_result(
                        STATUS_BAD_REQUEST,
                        "invalid_params",
                        "join continuation target and operation are required",
                    ));
                }
                if data.expected.is_empty() {
                    return Ok(error_result(
                        STATUS_BAD_REQUEST,
                        "invalid_params",
                        "join continuation requires non-empty expected",
                    ));
                }
                match data.dispatch_capability {
                    Some(h) => h,
                    None => {
                        return Ok(error_result(
                            STATUS_BAD_REQUEST,
                            "missing_dispatch_capability",
                            "install requires dispatch_capability for the deferred dispatch",
                        ));
                    }
                }
            }
        };

        // Step 2: §3.1a IN-CHAIN authorization check (CT2) via the unified
        // chain-walk primitive (V7 §5.5 check_creator_authority,
        // PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE). `check_creator_authority`
        // collects the full chain leaf-to-root and reports `found` iff the
        // author appears as a granter ANYWHERE in it — this is the §3.1a
        // in-chain check, NOT a chain-root check (a root check is correct
        // only for local continuations and fails every cross-peer one;
        // §3.1a, §4.2 case 3). Chain reachability errors (404) take
        // structural precedence over identity-not-found (403) because the
        // walker always reaches root before the identity scan.
        let author = match ctx.author {
            Some(a) => a,
            None => {
                return Ok(error_result(
                    STATUS_FORBIDDEN,
                    "missing_author",
                    "install requires authenticated author",
                ));
            }
        };
        let resolve = |h: &Hash| -> Option<Entity> {
            ctx.included
                .get(h)
                .cloned()
                .or_else(|| self.content_store.get(h))
        };
        let auth_result = match entity_protocol::check_creator_authority(
            &dispatch_cap,
            &author,
            &ctx.included,
            resolve,
        ) {
            Ok(r) => r,
            Err(_) => {
                // Both Unreachable and TooDeep map to 404 chain_unreachable
                // at the protocol boundary — the chain is effectively
                // unwalkable in either case.
                return Ok(error_result(
                    STATUS_NOT_FOUND,
                    "chain_unreachable",
                    "dispatch_capability authority chain has unreachable links",
                ));
            }
        };
        if !auth_result.found {
            // Per proposal §3.2: "Persistence only on found=true." The chain
            // collected for inspection MUST NOT land in the local store on
            // rejected requests.
            return Ok(error_result(
                STATUS_FORBIDDEN,
                "embedded_cap_unauthorized",
                "writer identity not in dispatch_capability authority chain",
            ));
        }

        // The continuation entity is the params itself. Persist directly —
        // no separate construction step from a wrapper. Resource targets are
        // peer-qualified by dispatch, so the location-index key matches what
        // a subsequent advance/resume/abandon will look up.
        let cont_hash = self
            .content_store
            .put(ctx.params.clone())
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        self.location_index.set(&qualified_path, cont_hash);

        // Step 5: persist the embedded capability and its full authority chain
        // to the local content store so future advance() can resolve it
        // (coherent-cap §2 chain-entity persistence). The chain was already
        // collected by `check_creator_authority` — no third walk needed
        // (PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §3.2). Caps are content-
        // addressed and `put` is idempotent, so re-persisting is safe.
        for cap_entity in auth_result.chain {
            let _ = self.content_store.put(cap_entity);
        }

        // Echo back the bare install path in the result for caller convenience;
        // resource targets arrive peer-qualified from dispatch.
        let bare_path = EntityUri::strip_peer_prefix(&qualified_path).to_string();
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("path"),
            entity_ecf::text(&bare_path),
        )]));
        let result = Entity::new(entity_types::TYPE_CONTINUATION_INSTALL_RESULT, data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        tracing::debug!(
            path = %bare_path,
            kind = %kind,
            "continuation install: completed"
        );

        Ok(HandlerResult {
            status: STATUS_OK,
            result,
            included: HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Resume operation
// ---------------------------------------------------------------------------

impl ContinuationHandler {
    async fn handle_resume(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let path = match ctx.resource_target.as_ref().and_then(|r| r.targets.first()) {
            Some(p) if !p.is_empty() => p.clone(),
            _ => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "resource target path required",
                ));
            }
        };

        let execute_fn = ctx
            .execute_fn
            .as_ref()
            .ok_or_else(|| HandlerError::Internal("execute_fn not available".into()))?;

        // Read suspended entity at path
        let hash = self.location_index.get(&path).ok_or_else(|| {
            HandlerError::Internal("not found".into())
        })?;
        let entity = self.content_store.get(&hash).ok_or_else(|| {
            HandlerError::Internal("entity not in store".into())
        })?;

        if entity.entity_type != "system/continuation/suspended" {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "not_suspended",
                "entity at path is not a suspended continuation",
            ));
        }

        let suspended = decode_suspended(&entity)?;

        // Decode resolution from request
        let resolution = decode_resume_request(&ctx.params.data)?;

        // Merge resolution into params
        let merged_params = merge_resolution(&suspended.params, &resolution)?;

        let params_entity = Entity::new("primitive/any", merged_params)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // Delete the suspended entity
        self.location_index.remove(&path);
        self.content_store.remove(&hash);

        // Dispatch to the suspended target
        let opts = ExecuteOptions {
            resource: suspended.resource.clone(),
            ..Default::default()
        };

        let result = execute_fn(
            suspended.target.clone(),
            suspended.operation.clone(),
            params_entity,
            opts,
        )
        .await?;

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Abandon operation
// ---------------------------------------------------------------------------

impl ContinuationHandler {
    async fn handle_abandon(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let path = match ctx.resource_target.as_ref().and_then(|r| r.targets.first()) {
            Some(p) if !p.is_empty() => p.clone(),
            _ => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "resource target path required",
                ));
            }
        };

        // Read suspended entity at path
        let hash = match self.location_index.get(&path) {
            Some(h) => h,
            None => {
                return Ok(error_result(STATUS_NOT_FOUND, "not_found", "nothing at path"));
            }
        };
        let entity = match self.content_store.get(&hash) {
            Some(e) => e,
            None => {
                return Ok(error_result(
                    STATUS_NOT_FOUND,
                    "not_found",
                    "entity not in store",
                ));
            }
        };

        if entity.entity_type != "system/continuation/suspended" {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "not_suspended",
                "entity at path is not a suspended continuation",
            ));
        }

        // Delete from tree and store
        self.location_index.remove(&path);
        self.content_store.remove(&hash);

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("abandoned"), entity_ecf::bool_val(true)),
            (entity_ecf::text("path"), entity_ecf::text(&path)),
        ]));
        let result = Entity::new("primitive/any", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ContinuationData {
    target: String,
    operation: String,
    resource: Option<entity_capability::ResourceTarget>,
    params: Option<Vec<u8>>,
    result_field: Option<String>,
    /// EXTENSION-CONTINUATION v1.16 §2.1: when true, the post-transform map
    /// value is shallow-merged into static `params` at top level (Merge
    /// dispatch-mode, §3.6 Step 2). Mutually exclusive with `result_field`
    /// (install rejects with `400 invalid_continuation`, §3.2).
    result_merge: bool,
    result_transform: Option<TransformData>,
    /// Per CONTINUATION §3.5: `on_error` is a `system/delivery-spec` —
    /// `{uri, operation}` (NOT a custom `{target, operation, deliver_to}`
    /// shape). Cross-impl fix: pre-fix
    /// Rust expected the wrong shape, decoded an empty target, and
    /// dispatched nowhere on the error path.
    on_error: Option<DeliverySpec>,
    deliver_to: Option<DeliverySpec>,
    remaining_executions: Option<u64>,
    dispatch_capability: Option<Hash>,
}

#[derive(Debug, Clone)]
struct TransformData {
    extract: Option<String>,
    select: Option<HashMap<String, String>>,
    /// EXTENSION-CONTINUATION v1.9 G1 §2.2: ordered bounded field ops,
    /// applied after extract/select, before the *_extract fields.
    transform_ops: Vec<TransformOp>,
    /// EXTENSION-CONTINUATION v1.7 §2.2 / §3.6: dotted paths into the
    /// post-extract/post-select/post-transform_ops value that override the
    /// static EXECUTE fields when present and resolvable.
    resource_extract: Option<String>,
    target_extract: Option<String>,
    operation_extract: Option<String>,
}

/// EXTENSION-CONTINUATION v1.9 §2.2 `system/continuation/transform-op`.
/// One bounded field op. All operand fields are optional and interpreted
/// per `op` (table in §2.2). The op set is total/pure/bounded — a missing
/// operand field is a documented no-op, never an error.
#[derive(Debug, Clone)]
struct TransformOp {
    op: String,
    field: Option<String>,
    into: Option<String>,
    fields: Option<Vec<String>>,
    prefix: Option<String>,
    literal: Option<String>,
    from: Option<String>,
    to: Option<String>,
    sep: Option<String>,
    range: Option<String>,
}

/// The recognized `transform_ops` op names (EXTENSION-CONTINUATION §2.2
/// table). An op not in this set MUST be rejected at install (fail-closed,
/// §8.1) — never silently skipped.
const KNOWN_TRANSFORM_OPS: &[&str] = &[
    "strip_prefix",
    "prepend",
    "append",
    "join",
    "replace_literal",
    "split",
    "slice",
    // EXTENSION-CONTINUATION v1.15 §2.2: map → keys projection. Singular
    // `{field, into}` or plural `{fields:[...], into}`; mutual exclusivity
    // enforced at install with 400 invalid_transform_args.
    "collect_keys",
    // EXTENSION-CONTINUATION v1.17 §2.2: read `field` as a system/hash and
    // replace it with the entity bound to that hash in the envelope's
    // `included` map. Pure envelope navigation (not a tree/store read);
    // total — miss/non-hash/absent ⇒ no-op. Lets a chain consume an entity
    // delivered in `envelope.included` (e.g. `include_payload` from
    // EXTENSION-SUBSCRIPTION §2.2) without a handler step.
    "deref_included",
];

#[derive(Debug, Clone)]
struct JoinData {
    expected: Vec<String>,
    received: HashMap<String, Vec<u8>>,
    target: String,
    operation: String,
    resource: Option<entity_capability::ResourceTarget>,
    params: Option<Vec<u8>>,
    result_field: Option<String>,
    on_error: Option<DeliverySpec>,
    deliver_to: Option<DeliverySpec>,
    remaining_executions: Option<u64>,
    dispatch_capability: Option<Hash>,
}

#[derive(Debug, Clone)]
struct SuspendedData {
    target: String,
    operation: String,
    resource: Option<entity_capability::ResourceTarget>,
    params: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Install request decode + entity builders
// ---------------------------------------------------------------------------

// `system/continuation/install-request` was eliminated by
// PROPOSAL-PATH-AS-RESOURCE-HYGIENE (P-CONTINUATION-1). Callers now pass a
// `system/continuation` or `system/continuation/join` entity directly as
// params; install path is the resource. See `handle_install`.

// ---------------------------------------------------------------------------
// CBOR decode helpers
// ---------------------------------------------------------------------------

fn decode_advance_request(params_data: &[u8]) -> Result<(Vec<u8>, Option<u32>), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(params_data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode params: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut result_bytes = Vec::new();
    let mut status = None;

    for (pk, pv) in map {
        match pk.as_text() {
            Some("result") => {
                result_bytes = match pv {
                    ciborium::Value::Bytes(b) => b.clone(),
                    _ => {
                        let mut buf = Vec::new();
                        ciborium::into_writer(pv, &mut buf).unwrap_or(());
                        buf
                    }
                };
            }
            Some("status") => {
                status = pv.as_integer().map(|i| i128::from(i) as u32);
            }
            _ => {}
        }
    }

    Ok((result_bytes, status))
}

fn decode_continuation(entity: &Entity) -> Result<ContinuationData, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
        .map_err(|e| HandlerError::InvalidParams(format!("decode continuation: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("continuation not a map".into()))?;

    let mut target = String::new();
    let mut operation = String::new();
    let mut resource = None;
    let mut params = None;
    let mut result_field = None;
    let mut result_merge = false;
    let mut result_transform = None;
    let mut on_error = None;
    let mut deliver_to = None;
    let mut remaining_executions = None;
    let mut dispatch_capability = None;

    for (k, v) in map {
        match k.as_text() {
            Some("target") => target = v.as_text().unwrap_or("").to_string(),
            Some("operation") => operation = v.as_text().unwrap_or("").to_string(),
            Some("resource") => resource = decode_resource_target(v),
            Some("params") => {
                params = Some(match v {
                    ciborium::Value::Bytes(b) => b.clone(),
                    _ => {
                        let mut buf = Vec::new();
                        ciborium::into_writer(v, &mut buf).unwrap_or(());
                        buf
                    }
                });
            }
            Some("result_field") => result_field = v.as_text().map(|s| s.to_string()),
            Some("result_merge") => {
                if let ciborium::Value::Bool(b) = v {
                    result_merge = *b;
                }
            }
            Some("result_transform") => result_transform = decode_transform(v),
            Some("on_error") => on_error = decode_on_error(v),
            Some("deliver_to") => deliver_to = decode_deliver_to(v),
            Some("remaining_executions") => {
                remaining_executions = v.as_integer().map(|i| i128::from(i) as u64);
            }
            Some("dispatch_capability") => {
                if let ciborium::Value::Bytes(b) = v {
                    dispatch_capability = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    Ok(ContinuationData {
        target,
        operation,
        resource,
        params,
        result_field,
        result_merge,
        result_transform,
        on_error,
        deliver_to,
        remaining_executions,
        dispatch_capability,
    })
}

fn decode_join(entity: &Entity) -> Result<JoinData, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
        .map_err(|e| HandlerError::InvalidParams(format!("decode join: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("join not a map".into()))?;

    let mut expected = Vec::new();
    let mut received = HashMap::new();
    let mut target = String::new();
    let mut operation = String::new();
    let mut resource = None;
    let mut params = None;
    let mut result_field = None;
    let mut on_error = None;
    let mut deliver_to = None;
    let mut remaining_executions = None;
    let mut dispatch_capability = None;

    for (k, v) in map {
        match k.as_text() {
            Some("expected") => {
                if let Some(arr) = v.as_array() {
                    expected = arr
                        .iter()
                        .filter_map(|e| e.as_text().map(|s| s.to_string()))
                        .collect();
                }
            }
            Some("received") => {
                if let Some(recv_map) = v.as_map() {
                    for (rk, rv) in recv_map {
                        if let Some(name) = rk.as_text() {
                            let bytes = match rv {
                                ciborium::Value::Bytes(b) => b.clone(),
                                _ => {
                                    let mut buf = Vec::new();
                                    ciborium::into_writer(rv, &mut buf).unwrap_or(());
                                    buf
                                }
                            };
                            received.insert(name.to_string(), bytes);
                        }
                    }
                }
            }
            Some("target") => target = v.as_text().unwrap_or("").to_string(),
            Some("operation") => operation = v.as_text().unwrap_or("").to_string(),
            Some("resource") => resource = decode_resource_target(v),
            Some("params") => {
                params = Some(match v {
                    ciborium::Value::Bytes(b) => b.clone(),
                    _ => {
                        let mut buf = Vec::new();
                        ciborium::into_writer(v, &mut buf).unwrap_or(());
                        buf
                    }
                });
            }
            Some("result_field") => result_field = v.as_text().map(|s| s.to_string()),
            Some("on_error") => on_error = decode_on_error(v),
            Some("deliver_to") => deliver_to = decode_deliver_to(v),
            Some("remaining_executions") => {
                remaining_executions = v.as_integer().map(|i| i128::from(i) as u64);
            }
            Some("dispatch_capability") => {
                if let ciborium::Value::Bytes(b) = v {
                    dispatch_capability = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    Ok(JoinData {
        expected,
        received,
        target,
        operation,
        resource,
        params,
        result_field,
        on_error,
        deliver_to,
        remaining_executions,
        dispatch_capability,
    })
}

fn decode_suspended(entity: &Entity) -> Result<SuspendedData, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
        .map_err(|e| HandlerError::InvalidParams(format!("decode suspended: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("suspended not a map".into()))?;

    let mut target = String::new();
    let mut operation = String::new();
    let mut resource = None;
    let mut params = None;

    for (k, v) in map {
        match k.as_text() {
            Some("target") => target = v.as_text().unwrap_or("").to_string(),
            Some("operation") => operation = v.as_text().unwrap_or("").to_string(),
            Some("resource") => resource = decode_resource_target(v),
            Some("params") => {
                params = Some(match v {
                    ciborium::Value::Bytes(b) => b.clone(),
                    _ => {
                        let mut buf = Vec::new();
                        ciborium::into_writer(v, &mut buf).unwrap_or(());
                        buf
                    }
                });
            }
            _ => {}
        }
    }

    Ok(SuspendedData {
        target,
        operation,
        resource,
        params,
    })
}

fn decode_resume_request(params_data: &[u8]) -> Result<Option<Vec<u8>>, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(params_data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode params: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    for (pk, pv) in map {
        if pk.as_text() == Some("resolution") {
            let bytes = match pv {
                ciborium::Value::Bytes(b) => b.clone(),
                _ => {
                    let mut buf = Vec::new();
                    ciborium::into_writer(pv, &mut buf).unwrap_or(());
                    buf
                }
            };
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn decode_resource_target(v: &ciborium::Value) -> Option<entity_capability::ResourceTarget> {
    let map = v.as_map()?;
    let mut targets = Vec::new();
    let mut exclude = Vec::new();
    for (k, v) in map {
        match k.as_text() {
            Some("targets") => {
                if let Some(arr) = v.as_array() {
                    targets = arr.iter().filter_map(|e| e.as_text().map(|s| s.to_string())).collect();
                }
            }
            Some("exclude") => {
                if let Some(arr) = v.as_array() {
                    exclude = arr.iter().filter_map(|e| e.as_text().map(|s| s.to_string())).collect();
                }
            }
            _ => {}
        }
    }
    if targets.is_empty() {
        None
    } else {
        Some(entity_capability::ResourceTarget { targets, exclude })
    }
}

fn decode_transform(v: &ciborium::Value) -> Option<TransformData> {
    let map = v.as_map()?;
    let mut extract = None;
    let mut select = None;
    let mut transform_ops = Vec::new();
    let mut resource_extract = None;
    let mut target_extract = None;
    let mut operation_extract = None;

    for (k, v) in map {
        match k.as_text() {
            Some("extract") => extract = v.as_text().map(|s| s.to_string()),
            Some("select") => {
                if let Some(sel_map) = v.as_map() {
                    let mut m = HashMap::new();
                    for (sk, sv) in sel_map {
                        if let (Some(key), Some(val)) = (sk.as_text(), sv.as_text()) {
                            m.insert(key.to_string(), val.to_string());
                        }
                    }
                    select = Some(m);
                }
            }
            // G1 §2.2: ordered list — preserve array order.
            Some("transform_ops") => {
                if let Some(arr) = v.as_array() {
                    transform_ops = arr.iter().filter_map(decode_transform_op).collect();
                }
            }
            Some("resource_extract") => {
                resource_extract = v.as_text().map(|s| s.to_string())
            }
            Some("target_extract") => target_extract = v.as_text().map(|s| s.to_string()),
            Some("operation_extract") => {
                operation_extract = v.as_text().map(|s| s.to_string())
            }
            _ => {}
        }
    }
    Some(TransformData {
        extract,
        select,
        transform_ops,
        resource_extract,
        target_extract,
        operation_extract,
    })
}

fn decode_transform_op(v: &ciborium::Value) -> Option<TransformOp> {
    let map = v.as_map()?;
    let mut op = String::new();
    let mut field = None;
    let mut into = None;
    let mut fields = None;
    let mut prefix = None;
    let mut literal = None;
    let mut from = None;
    let mut to = None;
    let mut sep = None;
    let mut range = None;
    for (k, val) in map {
        match k.as_text() {
            Some("op") => op = val.as_text().unwrap_or("").to_string(),
            Some("field") => field = val.as_text().map(|s| s.to_string()),
            Some("into") => into = val.as_text().map(|s| s.to_string()),
            Some("fields") => {
                if let Some(arr) = val.as_array() {
                    fields = Some(
                        arr.iter()
                            .filter_map(|e| e.as_text().map(|s| s.to_string()))
                            .collect(),
                    );
                }
            }
            Some("prefix") => prefix = val.as_text().map(|s| s.to_string()),
            Some("literal") => literal = val.as_text().map(|s| s.to_string()),
            Some("from") => from = val.as_text().map(|s| s.to_string()),
            Some("to") => to = val.as_text().map(|s| s.to_string()),
            Some("sep") => sep = val.as_text().map(|s| s.to_string()),
            Some("range") => range = val.as_text().map(|s| s.to_string()),
            _ => {}
        }
    }
    if op.is_empty() {
        return None;
    }
    Some(TransformOp {
        op,
        field,
        into,
        fields,
        prefix,
        literal,
        from,
        to,
        sep,
        range,
    })
}

/// Per CONTINUATION §3.5: `on_error` is a `system/delivery-spec`
/// (`{uri, operation}`). Same wire shape as `deliver_to`; reuses the
/// delivery-spec decoder. Cross-impl fix.
fn decode_on_error(v: &ciborium::Value) -> Option<DeliverySpec> {
    decode_deliver_to(v)
}

fn decode_deliver_to(v: &ciborium::Value) -> Option<DeliverySpec> {
    let map = v.as_map()?;
    let mut uri = String::new();
    let mut operation = String::new();
    for (k, v) in map {
        match k.as_text() {
            Some("uri") => uri = v.as_text().unwrap_or("").to_string(),
            Some("operation") => operation = v.as_text().unwrap_or("").to_string(),
            _ => {}
        }
    }
    if uri.is_empty() {
        None
    } else {
        Some(DeliverySpec { uri, operation })
    }
}

// ---------------------------------------------------------------------------
// CBOR encode helpers
// ---------------------------------------------------------------------------

fn encode_continuation(cont: &ContinuationData) -> Vec<u8> {
    let mut fields = vec![
        (entity_ecf::text("operation"), entity_ecf::text(&cont.operation)),
        (entity_ecf::text("target"), entity_ecf::text(&cont.target)),
    ];

    if let Some(ref dt) = cont.deliver_to {
        fields.push((
            entity_ecf::text("deliver_to"),
            entity_ecf::Value::Map(vec![
                (entity_ecf::text("operation"), entity_ecf::text(&dt.operation)),
                (entity_ecf::text("uri"), entity_ecf::text(&dt.uri)),
            ]),
        ));
    }
    if let Some(cap) = cont.dispatch_capability {
        fields.push((
            entity_ecf::text("dispatch_capability"),
            entity_ecf::Value::Bytes(cap.to_bytes().to_vec()),
        ));
    }
    if let Some(ref oe) = cont.on_error {
        // Per CONTINUATION §3.5: `on_error` is a `system/delivery-spec`
        // (`{operation, uri}`). Cross-impl fix.
        fields.push((
            entity_ecf::text("on_error"),
            entity_ecf::Value::Map(vec![
                (entity_ecf::text("operation"), entity_ecf::text(&oe.operation)),
                (entity_ecf::text("uri"), entity_ecf::text(&oe.uri)),
            ]),
        ));
    }
    if let Some(ref p) = cont.params {
        // `params` is `primitive/any` per EXTENSION-CONTINUATION §2.1 and is
        // encoded as the CBOR data item inline per ENTITY-CBOR-ENCODING §7.6.1
        // (`primitive/any` = `any` CBOR data item). Splice raw CBOR by
        // round-tripping through `from_reader` so `to_ecf` re-canonicalizes.
        // Earlier versions wrote `Value::Bytes(p.clone())` here, which
        // mis-encoded params as `primitive/bytes` and broke cross-impl interop
        // with Go's `cbor.RawMessage` shape. Decoders already accept both.
        let v: ciborium::Value =
            ciborium::from_reader(p.as_slice()).unwrap_or(ciborium::Value::Null);
        fields.push((entity_ecf::text("params"), v));
    }
    if let Some(n) = cont.remaining_executions {
        fields.push((
            entity_ecf::text("remaining_executions"),
            entity_ecf::integer(n as i64),
        ));
    }
    if let Some(ref res) = cont.resource {
        fields.push((entity_ecf::text("resource"), encode_resource_target(res)));
    }
    if let Some(ref rf) = cont.result_field {
        fields.push((entity_ecf::text("result_field"), entity_ecf::text(rf)));
    }
    // EXTENSION-CONTINUATION v1.16 §2.1: emit `result_merge` only when true
    // (omitempty per the spec). Decoders default to false on absence.
    if cont.result_merge {
        fields.push((entity_ecf::text("result_merge"), entity_ecf::bool_val(true)));
    }
    if let Some(ref rt) = cont.result_transform {
        fields.push((entity_ecf::text("result_transform"), encode_transform(rt)));
    }

    entity_ecf::to_ecf(&entity_ecf::Value::Map(fields))
}

fn encode_join(join: &JoinData) -> Vec<u8> {
    let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();

    if let Some(ref dt) = join.deliver_to {
        fields.push((
            entity_ecf::text("deliver_to"),
            entity_ecf::Value::Map(vec![
                (entity_ecf::text("operation"), entity_ecf::text(&dt.operation)),
                (entity_ecf::text("uri"), entity_ecf::text(&dt.uri)),
            ]),
        ));
    }
    if let Some(cap) = join.dispatch_capability {
        fields.push((
            entity_ecf::text("dispatch_capability"),
            entity_ecf::Value::Bytes(cap.to_bytes().to_vec()),
        ));
    }
    let expected_arr: Vec<entity_ecf::Value> =
        join.expected.iter().map(entity_ecf::text).collect();
    fields.push((
        entity_ecf::text("expected"),
        entity_ecf::Value::Array(expected_arr),
    ));
    if let Some(ref oe) = join.on_error {
        // Per CONTINUATION §3.5: `on_error` is a `system/delivery-spec`.
        fields.push((
            entity_ecf::text("on_error"),
            entity_ecf::Value::Map(vec![
                (entity_ecf::text("operation"), entity_ecf::text(&oe.operation)),
                (entity_ecf::text("uri"), entity_ecf::text(&oe.uri)),
            ]),
        ));
    }
    fields.push((entity_ecf::text("operation"), entity_ecf::text(&join.operation)));
    if let Some(ref p) = join.params {
        // `params` is `primitive/any` — splice inline per ENTITY-CBOR-ENCODING
        // §7.6.1. See note in encode_continuation.
        let v: ciborium::Value =
            ciborium::from_reader(p.as_slice()).unwrap_or(ciborium::Value::Null);
        fields.push((entity_ecf::text("params"), v));
    }
    // received map: each slot value is `primitive/any` per
    // EXTENSION-CONTINUATION §2.3 (`received: map_of: primitive/any`) — splice
    // inline, don't wrap as `bytes()`.
    let received_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = join
        .received
        .iter()
        .map(|(k, v)| {
            let val: ciborium::Value =
                ciborium::from_reader(v.as_slice()).unwrap_or(ciborium::Value::Null);
            (entity_ecf::text(k), val)
        })
        .collect();
    fields.push((entity_ecf::text("received"), entity_ecf::Value::Map(received_pairs)));
    if let Some(n) = join.remaining_executions {
        fields.push((
            entity_ecf::text("remaining_executions"),
            entity_ecf::integer(n as i64),
        ));
    }
    if let Some(ref res) = join.resource {
        fields.push((entity_ecf::text("resource"), encode_resource_target(res)));
    }
    if let Some(ref rf) = join.result_field {
        fields.push((entity_ecf::text("result_field"), entity_ecf::text(rf)));
    }
    fields.push((entity_ecf::text("target"), entity_ecf::text(&join.target)));

    entity_ecf::to_ecf(&entity_ecf::Value::Map(fields))
}

fn encode_resource_target(rt: &entity_capability::ResourceTarget) -> entity_ecf::Value {
    let mut fields = vec![];
    if !rt.exclude.is_empty() {
        let arr: Vec<entity_ecf::Value> = rt.exclude.iter().map(entity_ecf::text).collect();
        fields.push((entity_ecf::text("exclude"), entity_ecf::Value::Array(arr)));
    }
    let targets: Vec<entity_ecf::Value> = rt.targets.iter().map(entity_ecf::text).collect();
    fields.push((entity_ecf::text("targets"), entity_ecf::Value::Array(targets)));
    entity_ecf::Value::Map(fields)
}

fn encode_transform(t: &TransformData) -> entity_ecf::Value {
    let mut fields = vec![];
    if let Some(ref e) = t.extract {
        fields.push((entity_ecf::text("extract"), entity_ecf::text(e)));
    }
    if let Some(ref op) = t.operation_extract {
        fields.push((entity_ecf::text("operation_extract"), entity_ecf::text(op)));
    }
    if let Some(ref re) = t.resource_extract {
        fields.push((entity_ecf::text("resource_extract"), entity_ecf::text(re)));
    }
    if let Some(ref s) = t.select {
        let pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = s
            .iter()
            .map(|(k, v)| (entity_ecf::text(k), entity_ecf::text(v)))
            .collect();
        fields.push((entity_ecf::text("select"), entity_ecf::Value::Map(pairs)));
    }
    if let Some(ref te) = t.target_extract {
        fields.push((entity_ecf::text("target_extract"), entity_ecf::text(te)));
    }
    // G1 §2.2: ordered list — Array preserves op order through to_ecf.
    if !t.transform_ops.is_empty() {
        let ops: Vec<entity_ecf::Value> =
            t.transform_ops.iter().map(encode_transform_op).collect();
        fields.push((
            entity_ecf::text("transform_ops"),
            entity_ecf::Value::Array(ops),
        ));
    }
    entity_ecf::Value::Map(fields)
}

fn encode_transform_op(o: &TransformOp) -> entity_ecf::Value {
    let mut fields = vec![(entity_ecf::text("op"), entity_ecf::text(&o.op))];
    if let Some(ref f) = o.field {
        fields.push((entity_ecf::text("field"), entity_ecf::text(f)));
    }
    if let Some(ref i) = o.into {
        fields.push((entity_ecf::text("into"), entity_ecf::text(i)));
    }
    if let Some(ref fs) = o.fields {
        let arr: Vec<entity_ecf::Value> = fs.iter().map(entity_ecf::text).collect();
        fields.push((entity_ecf::text("fields"), entity_ecf::Value::Array(arr)));
    }
    if let Some(ref p) = o.prefix {
        fields.push((entity_ecf::text("prefix"), entity_ecf::text(p)));
    }
    if let Some(ref l) = o.literal {
        fields.push((entity_ecf::text("literal"), entity_ecf::text(l)));
    }
    if let Some(ref f) = o.from {
        fields.push((entity_ecf::text("from"), entity_ecf::text(f)));
    }
    if let Some(ref tt) = o.to {
        fields.push((entity_ecf::text("to"), entity_ecf::text(tt)));
    }
    if let Some(ref s) = o.sep {
        fields.push((entity_ecf::text("sep"), entity_ecf::text(s)));
    }
    if let Some(ref r) = o.range {
        fields.push((entity_ecf::text("range"), entity_ecf::text(r)));
    }
    entity_ecf::Value::Map(fields)
}

fn encode_received_map(received: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    // Each slot value is `primitive/any` per EXTENSION-CONTINUATION §2.3 —
    // splice inline, not wrap. See note in encode_continuation.
    let pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = received
        .iter()
        .map(|(k, v)| {
            let val: ciborium::Value =
                ciborium::from_reader(v.as_slice()).unwrap_or(ciborium::Value::Null);
            (entity_ecf::text(k), val)
        })
        .collect();
    entity_ecf::to_ecf(&entity_ecf::Value::Map(pairs))
}

// ---------------------------------------------------------------------------
// Transform + assemble logic
// ---------------------------------------------------------------------------

/// Run the result transform pipeline (EXTENSION-CONTINUATION §2.2 / §3.6):
/// `extract -> select -> transform_ops`, in that order, on the same value.
/// Returns the post-pipeline value encoded as bytes — the SINGLE value that
/// both dispatch-mode params assembly and the `*_extract` EXECUTE-field
/// resolution operate on (§2.2: "both operate on the post-extract/post-select
/// value").
///
/// Best-effort and total: transforms MUST NOT produce errors (§2.2). On
/// result CBOR-decode failure, or an `extract` path that misses, the
/// original unmodified result bytes pass through. A `select` source that
/// misses yields a null entry (not a fallback to the original).
fn apply_transform(
    result_bytes: &[u8],
    transform: &Option<TransformData>,
    included: &HashMap<Hash, Entity>,
) -> Result<Vec<u8>, HandlerError> {
    let transform = match transform {
        Some(t) => t,
        None => return Ok(result_bytes.to_vec()),
    };

    // §2.2: CBOR decode failure ⇒ pass original unmodified result through.
    let mut value: ciborium::Value = match ciborium::from_reader(result_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(result_bytes.to_vec()),
    };

    // 1. extract — miss ⇒ keep prior value (pass-through), never error.
    if let Some(ref extract_path) = transform.extract {
        if let Some(extracted) = navigate_opt(&value, extract_path) {
            value = extracted;
        }
    }

    // 2. select — operates on the (post-extract) value; missing source ⇒
    //    null entry. An all-null map is passed through as-is (§2.2).
    if let Some(ref select_map) = transform.select {
        let mut pairs = Vec::new();
        for (dest_key, source_path) in select_map {
            let v = navigate_opt(&value, source_path).unwrap_or(ciborium::Value::Null);
            pairs.push((ciborium::Value::Text(dest_key.clone()), v));
        }
        value = ciborium::Value::Map(pairs);
    }

    // 3. transform_ops — applied after extract/select, before *_extract.
    for op in &transform.transform_ops {
        value = apply_transform_op(value, op, included);
    }

    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf)
        .map_err(|e| HandlerError::Internal(format!("encode transformed: {}", e)))?;
    Ok(buf)
}

// `error_code_from_result` removed in v1.19 migration — replaced by
// `read_result_code` (returns Option<String>) which the new v1.19 §3.10.5
// `{reason}` = `result.data.code` single-rule flow uses directly.


/// Best-effort dotted-path navigation: `None` if any segment is missing or
/// the value is not a map at that point. Unlike [`navigate_path`], never
/// errors — the §2.2 "transforms do not produce errors" contract.
fn navigate_opt(val: &ciborium::Value, path: &str) -> Option<ciborium::Value> {
    let mut current = val.clone();
    for segment in path.split('.') {
        let map = current.as_map()?;
        let found = map
            .iter()
            .find(|(k, _)| k.as_text() == Some(segment))
            .map(|(_, v)| v.clone())?;
        current = found;
    }
    Some(current)
}

/// Apply one `transform_ops` op to the pipeline value (EXTENSION-CONTINUATION
/// §2.2). Total/pure/bounded: ops address named fields of a map value; a
/// missing field, wrong value type, or non-map input is a documented no-op
/// (returns the value unchanged). Unknown `op` is rejected at install
/// (`validate_transform_ops`), so by the time this runs every op is known.
fn apply_transform_op(
    value: ciborium::Value,
    op: &TransformOp,
    included: &HashMap<Hash, Entity>,
) -> ciborium::Value {
    let mut pairs = match value {
        ciborium::Value::Map(m) => m,
        // Ops are field plumbing on a map; anything else ⇒ no-op (total).
        other => return other,
    };

    // Read a string field by name from the current map.
    let get_str = |pairs: &[(ciborium::Value, ciborium::Value)], name: &str| -> Option<String> {
        pairs
            .iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .and_then(|(_, v)| v.as_text().map(|s| s.to_string()))
    };
    // Set (replace-or-insert) a field to a value.
    fn set_field(
        pairs: &mut Vec<(ciborium::Value, ciborium::Value)>,
        name: &str,
        v: ciborium::Value,
    ) {
        pairs.retain(|(k, _)| k.as_text() != Some(name));
        pairs.push((ciborium::Value::Text(name.to_string()), v));
    }

    match op.op.as_str() {
        "strip_prefix" => {
            if let (Some(field), Some(prefix)) = (&op.field, &op.prefix) {
                if let Some(s) = get_str(&pairs, field) {
                    let out = s.strip_prefix(prefix.as_str()).unwrap_or(&s).to_string();
                    set_field(&mut pairs, field, ciborium::Value::Text(out));
                }
            }
        }
        "prepend" => {
            if let (Some(field), Some(lit)) = (&op.field, &op.literal) {
                if let Some(s) = get_str(&pairs, field) {
                    set_field(
                        &mut pairs,
                        field,
                        ciborium::Value::Text(format!("{lit}{s}")),
                    );
                }
            }
        }
        "append" => {
            if let (Some(field), Some(lit)) = (&op.field, &op.literal) {
                if let Some(s) = get_str(&pairs, field) {
                    set_field(
                        &mut pairs,
                        field,
                        ciborium::Value::Text(format!("{s}{lit}")),
                    );
                }
            }
        }
        "join" => {
            if let (Some(fields), Some(into)) = (&op.fields, &op.into) {
                let sep = op.sep.as_deref().unwrap_or("");
                let parts: Vec<String> = fields
                    .iter()
                    .map(|f| get_str(&pairs, f).unwrap_or_default())
                    .collect();
                set_field(
                    &mut pairs,
                    into,
                    ciborium::Value::Text(parts.join(sep)),
                );
            }
        }
        "replace_literal" => {
            if let (Some(field), Some(from), Some(to)) = (&op.field, &op.from, &op.to) {
                if let Some(s) = get_str(&pairs, field) {
                    set_field(
                        &mut pairs,
                        field,
                        ciborium::Value::Text(s.replace(from.as_str(), to)),
                    );
                }
            }
        }
        "split" => {
            if let (Some(field), Some(sep), Some(into)) =
                (&op.field, &op.sep, &op.into)
            {
                if let Some(s) = get_str(&pairs, field) {
                    let parts: Vec<ciborium::Value> = s
                        .split(sep.as_str())
                        .map(|p| ciborium::Value::Text(p.to_string()))
                        .collect();
                    set_field(&mut pairs, into, ciborium::Value::Array(parts));
                }
            }
        }
        "slice" => {
            if let (Some(field), Some(range), Some(into)) =
                (&op.field, &op.range, &op.into)
            {
                if let Some(s) = get_str(&pairs, field) {
                    let sliced = slice_by_range(&s, range);
                    set_field(&mut pairs, into, ciborium::Value::Text(sliced));
                }
            }
        }
        // EXTENSION-CONTINUATION v1.15 §2.2: project map keys into an array
        // at `into`. Singular `field` projects one map's keys; plural
        // `fields:[...]` concatenates each listed map's keys in list order.
        // Field navigation follows the dotted-path rules from `extract`.
        //
        // Best-effort rules per §2.2:
        // - Empty `into` (absent or empty string) → silent no-op (no write).
        // - Empty map source → write empty array.
        // - Singular form, missing or non-map source → no-op (no write).
        // - Plural form: missing/non-map entries are individually skipped;
        //   surviving maps' keys are concatenated; if every entry is missing
        //   the result is still an empty-array write (concatenation of zero
        //   maps is the empty array).
        //
        // Mutual exclusivity (both `field` and `fields`) is rejected at
        // install (`validate_transform_ops` → `InvalidArgs`); apply never
        // sees both set.
        "collect_keys" => {
            let into = match op.into.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => return ciborium::Value::Map(pairs),
            };
            let cur = ciborium::Value::Map(pairs.clone());
            let mut keys: Vec<ciborium::Value> = Vec::new();
            let write = match (&op.field, &op.fields) {
                (Some(f), None) => {
                    // Singular: missing or non-map source is no-op.
                    match navigate_opt(&cur, f).as_ref().and_then(|v| v.as_map()) {
                        Some(m) => {
                            for (k, _) in m {
                                if let Some(s) = k.as_text() {
                                    keys.push(ciborium::Value::Text(s.to_string()));
                                }
                            }
                            true
                        }
                        None => false,
                    }
                }
                (None, Some(fs)) => {
                    // Plural: skip missing/non-map individually; still write
                    // the (possibly empty) concatenation.
                    for src in fs {
                        let Some(v) = navigate_opt(&cur, src) else { continue };
                        let Some(m) = v.as_map() else { continue };
                        for (k, _) in m {
                            if let Some(s) = k.as_text() {
                                keys.push(ciborium::Value::Text(s.to_string()));
                            }
                        }
                    }
                    true
                }
                // Neither `field` nor `fields` set: no-op.
                _ => false,
            };
            if write {
                set_field(&mut pairs, into, ciborium::Value::Array(keys));
            }
        }
        // EXTENSION-CONTINUATION v1.17 §2.2: read `field` as a system/hash and
        // replace it with the entity bound to that hash in the envelope's
        // `included` map. Pure envelope navigation (§3.1 receiver already
        // resolves EXECUTE.data hash-refs from `included`; this exposes the
        // same navigation to transforms — NOT a tree/store read). Total:
        //   - field missing from the map → no-op
        //   - field present but not bytes (not a hash) → no-op
        //   - field is bytes but Hash::from_bytes fails → no-op
        //   - hash absent from `included` → no-op
        // On hit, the entity is written back as a map {type, data, content_hash}
        // — the same inline-entity shape that EXECUTE.params uses (§3.4), so
        // downstream `extract`/`select`/`apply` see a familiar structure and
        // assemble_params can splice it directly.
        "deref_included" => {
            if let Some(field) = &op.field {
                if let Some(field_val) = pairs
                    .iter()
                    .find(|(k, _)| k.as_text() == Some(field.as_str()))
                    .map(|(_, v)| v.clone())
                {
                    if let ciborium::Value::Bytes(bytes) = field_val {
                        if let Ok(h) = Hash::from_bytes(&bytes) {
                            if let Some(entity) = included.get(&h) {
                                let data_val: ciborium::Value =
                                    ciborium::from_reader(entity.data.as_slice())
                                        .unwrap_or(ciborium::Value::Bytes(entity.data.clone()));
                                let inline = ciborium::Value::Map(vec![
                                    (
                                        ciborium::Value::Text("content_hash".to_string()),
                                        ciborium::Value::Bytes(h.to_bytes().to_vec()),
                                    ),
                                    (ciborium::Value::Text("data".to_string()), data_val),
                                    (
                                        ciborium::Value::Text("type".to_string()),
                                        ciborium::Value::Text(entity.entity_type.clone()),
                                    ),
                                ]);
                                set_field(&mut pairs, field, inline);
                            }
                        }
                    }
                }
            }
        }
        // Unreachable: validate_transform_ops rejects unknown ops at install
        // (§8.1 fail-closed). Defensive no-op if it ever slips through.
        _ => {}
    }

    ciborium::Value::Map(pairs)
}

/// Bounded char-slice by a `"start:end"` range (either side may be empty for
/// open-ended). Out-of-range / unparseable ⇒ the original string (total).
fn slice_by_range(s: &str, range: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let (lo, hi) = match range.split_once(':') {
        Some((a, b)) => {
            let lo = if a.is_empty() {
                0
            } else {
                match a.parse::<usize>() {
                    Ok(v) => v,
                    Err(_) => return s.to_string(),
                }
            };
            let hi = if b.is_empty() {
                n
            } else {
                match b.parse::<usize>() {
                    Ok(v) => v,
                    Err(_) => return s.to_string(),
                }
            };
            (lo, hi)
        }
        None => return s.to_string(),
    };
    if lo > hi || lo > n {
        return s.to_string();
    }
    chars[lo..hi.min(n)].iter().collect()
}

/// Install-time validation outcome for `transform_ops`.
/// Distinguishes the two install-time rejection contracts:
/// - `UnknownOp(name)` → fail-closed unknown `op` (§2.2 / §8.1 G1),
///   status `400 unknown_transform_op`.
/// - `InvalidArgs(message)` → recognized op with invalid args (§2.2,
///   v1.15: `collect_keys` mutual exclusivity), status
///   `400 invalid_transform_args`.
enum TransformOpsError {
    UnknownOp(String),
    InvalidArgs(String),
}

/// Validate `transform_ops` at install (EXTENSION-CONTINUATION §8.1, G1 +
/// v1.15 collect_keys mutual exclusivity). Returns the first failure.
fn validate_transform_ops(
    transform: &Option<TransformData>,
) -> Result<(), TransformOpsError> {
    if let Some(t) = transform {
        for op in &t.transform_ops {
            if !KNOWN_TRANSFORM_OPS.contains(&op.op.as_str()) {
                return Err(TransformOpsError::UnknownOp(op.op.clone()));
            }
            // v1.15 §2.2: collect_keys MUST NOT carry both `field` and
            // `fields`. The op IS recognized; the args are invalid.
            if op.op == "collect_keys"
                && op.field.is_some()
                && op.fields.is_some()
            {
                return Err(TransformOpsError::InvalidArgs(
                    "collect_keys: field and fields are mutually exclusive"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// EXTENSION-CONTINUATION §3.6 `resolve_or_default`: a `*_extract` dotted
/// path into the post-pipeline value overrides the static EXECUTE field
/// when present AND it resolves to a non-null string; otherwise the static
/// default is used.
fn resolve_or_default(
    value: &ciborium::Value,
    extract_path: &Option<String>,
    default: &str,
) -> String {
    let path = match extract_path {
        Some(p) => p,
        None => return default.to_string(),
    };
    match navigate_opt(value, path) {
        Some(ciborium::Value::Text(s)) => s,
        _ => default.to_string(),
    }
}

/// EXTENSION-CONTINUATION §3.6 `resolve_or_default_resource`: like
/// [`resolve_or_default`] but wraps the extracted value into a
/// `system/protocol/resource-target` — string ⇒ `{targets:[s]}`, array of
/// strings ⇒ `{targets: arr}`, an object already shaped as a resource
/// target ⇒ as-is. Navigation miss / unusable shape ⇒ static default.
fn resolve_or_default_resource(
    value: &ciborium::Value,
    extract_path: &Option<String>,
    default: &Option<entity_capability::ResourceTarget>,
) -> Option<entity_capability::ResourceTarget> {
    let path = match extract_path {
        Some(p) => p,
        None => return default.clone(),
    };
    let extracted = match navigate_opt(value, path) {
        Some(v) => v,
        None => return default.clone(),
    };
    match extracted {
        ciborium::Value::Text(s) => Some(entity_capability::ResourceTarget {
            targets: vec![s],
            exclude: Vec::new(),
        }),
        ciborium::Value::Array(arr) => {
            let targets: Vec<String> = arr
                .iter()
                .filter_map(|e| e.as_text().map(|s| s.to_string()))
                .collect();
            if targets.is_empty() {
                default.clone()
            } else {
                Some(entity_capability::ResourceTarget {
                    targets,
                    exclude: Vec::new(),
                })
            }
        }
        ciborium::Value::Map(_) => {
            // Already a well-formed resource target object? (has `targets`)
            decode_resource_target(&extracted).or_else(|| default.clone())
        }
        _ => default.clone(),
    }
}

// `navigate_path` (erroring on a missing segment) was removed in v1.9:
// EXTENSION-CONTINUATION §2.2 mandates transforms are best-effort and MUST
// NOT produce errors, so all navigation now goes through `navigate_opt`
// (miss ⇒ None, never Err). Keeping the erroring variant invited
// reintroducing the §2.2 violation.

/// EXTENSION-CONTINUATION v1.16 §3.6 Step 2 — Merge dispatch-mode.
///
/// Shallow-union the post-transform map value into static `cont_params` at
/// top level. Result keys win on collision. A non-map value degrades to
/// static-only params (caller is expected to bind a `merge_value_not_map`
/// lost-error marker per §3.4). Returns `(assembled_params, degraded)`
/// where `degraded` is true iff the transformed value was not a map.
fn assemble_params_merge(
    cont_params: &Option<Vec<u8>>,
    transformed: &[u8],
) -> Result<(Vec<u8>, bool), HandlerError> {
    let result_val: ciborium::Value = ciborium::from_reader(transformed)
        .map_err(|e| HandlerError::InvalidParams(format!("decode result: {}", e)))?;
    let static_val: ciborium::Value = match cont_params {
        Some(bytes) => ciborium::from_reader(bytes.as_slice())
            .map_err(|e| HandlerError::InvalidParams(format!("decode params: {}", e)))?,
        None => ciborium::Value::Map(Vec::new()),
    };

    let static_map = match static_val {
        ciborium::Value::Map(m) => m,
        ciborium::Value::Null => Vec::new(),
        _ => {
            return Err(HandlerError::InvalidParams(
                "result_merge requires static params to be a map (or absent)".into(),
            ));
        }
    };

    let result_map = match result_val {
        ciborium::Value::Map(m) => m,
        _ => {
            // Degrade: static-only params, caller emits lost-error marker.
            let mut buf = Vec::new();
            ciborium::into_writer(&ciborium::Value::Map(static_map), &mut buf)
                .map_err(|e| HandlerError::Internal(format!("encode static: {}", e)))?;
            return Ok((buf, true));
        }
    };

    // Shallow union: start with static, replace any key the result also
    // sets. Result keys win on collision.
    let mut merged: Vec<(ciborium::Value, ciborium::Value)> = static_map;
    for (rk, rv) in result_map {
        merged.retain(|(k, _)| {
            // Compare by text-key when both are text, else fall back to
            // value equality on the key.
            match (k.as_text(), rk.as_text()) {
                (Some(a), Some(b)) => a != b,
                _ => k != &rk,
            }
        });
        merged.push((rk, rv));
    }

    let mut buf = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(merged), &mut buf)
        .map_err(|e| HandlerError::Internal(format!("encode merged: {}", e)))?;
    Ok((buf, false))
}

/// Assemble dispatch params from continuation params, result_field, and result value.
fn assemble_params(
    cont_params: &Option<Vec<u8>>,
    result_field: &Option<String>,
    result_bytes: &[u8],
) -> Result<Vec<u8>, HandlerError> {
    match (cont_params, result_field) {
        // Neither params nor result_field: pass-through
        (None, None) => Ok(result_bytes.to_vec()),

        // Params + result_field: inject
        (Some(params_bytes), Some(field)) => {
            let mut params_val: ciborium::Value =
                ciborium::from_reader(params_bytes.as_slice())
                    .map_err(|e| HandlerError::InvalidParams(format!("decode params: {}", e)))?;
            let result_val: ciborium::Value =
                ciborium::from_reader(result_bytes)
                    .map_err(|e| HandlerError::InvalidParams(format!("decode result: {}", e)))?;

            if let ciborium::Value::Map(ref mut map) = params_val {
                // Remove existing field if present, then add
                map.retain(|(k, _)| k.as_text() != Some(field));
                map.push((ciborium::Value::Text(field.clone()), result_val));
            } else {
                return Err(HandlerError::InvalidParams("params not a map for injection".into()));
            }

            let mut buf = Vec::new();
            ciborium::into_writer(&params_val, &mut buf)
                .map_err(|e| HandlerError::Internal(format!("encode assembled: {}", e)))?;
            Ok(buf)
        }

        // Params but no result_field: trigger mode
        (Some(params_bytes), None) => Ok(params_bytes.clone()),

        // result_field without params: error
        (None, Some(_)) => Err(HandlerError::InvalidParams(
            "result_field without params is invalid".into(),
        )),
    }
}

/// Merge resolution into suspended params.
fn merge_resolution(
    params: &Option<Vec<u8>>,
    resolution: &Option<Vec<u8>>,
) -> Result<Vec<u8>, HandlerError> {
    match (params, resolution) {
        (Some(p), Some(r)) => {
            let mut params_val: ciborium::Value =
                ciborium::from_reader(p.as_slice())
                    .map_err(|e| HandlerError::InvalidParams(format!("decode params: {}", e)))?;
            let res_val: ciborium::Value =
                ciborium::from_reader(r.as_slice())
                    .map_err(|e| HandlerError::InvalidParams(format!("decode resolution: {}", e)))?;

            if let (ciborium::Value::Map(ref mut pm), ciborium::Value::Map(rm)) =
                (&mut params_val, res_val)
            {
                for (k, v) in rm {
                    // Resolution keys overwrite params
                    pm.retain(|(pk, _)| pk != &k);
                    pm.push((k, v));
                }
            }

            let mut buf = Vec::new();
            ciborium::into_writer(&params_val, &mut buf)
                .map_err(|e| HandlerError::Internal(format!("encode merged: {}", e)))?;
            Ok(buf)
        }
        (Some(p), None) => Ok(p.clone()),
        (None, Some(r)) => Ok(r.clone()),
        (None, None) => Ok(entity_ecf::to_ecf(&entity_ecf::Value::Null)),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn advancement_result(advanced: bool) -> HandlerResult {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("advanced"),
        entity_ecf::bool_val(advanced),
    )]));
    let result = Entity::new("system/continuation/advancement-result", data).unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
    included: std::collections::HashMap::new(),
    }
}

fn advancement_not_found() -> HandlerResult {
    advancement_result(false)
}

fn error_result(status: u32, code: &str, message: &str) -> HandlerResult {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    // Canonical error entity type per `entity_types::TYPE_ERROR`. The
    // cross-impl validator keys on this type to extract `code` from
    // `data`; a non-canonical type leaves consumers (SDKs, conformance
    // probes) defaulting to a generic `bad_request` and surfacing as a
    // false-negative finding (R-1, Go cross-impl validation).
    let result = Entity::new(entity_types::TYPE_ERROR, data).unwrap();
    HandlerResult { status, result, included: std::collections::HashMap::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id() -> String {
        entity_crypto::Keypair::from_seed([42u8; 32]).peer_id().to_string()
    }

    fn make_handler() -> ContinuationHandler {
        ContinuationHandler::new(
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
            test_peer_id(),
        )
    }

    #[test]
    fn test_pattern() {
        let h = make_handler();
        let expected = format!("/{}/system/continuation", test_peer_id());
        assert_eq!(h.pattern(), expected);
        assert_eq!(h.name(), "continuations");
        assert_eq!(h.operations(), &["install", "advance", "resume", "abandon"]);
    }

    fn make_params(data: entity_ecf::Value) -> Entity {
        Entity::new("primitive/null", entity_ecf::to_ecf(&data)).unwrap()
    }

    fn make_execute() -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("request_id"), entity_ecf::text("r1")),
        ]));
        Entity::new(entity_types::TYPE_EXECUTE, data).unwrap()
    }

    #[tokio::test]
    async fn test_unknown_operation() {
        let h = make_handler();
        let ctx = HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: make_execute(),
            params: make_params(entity_ecf::Value::Null),
            pattern: format!("/{}/system/continuation", test_peer_id()),
            suffix: String::new(),
            resource_target: None,
            author: None,
            session_peer_id: None,
            request_id: "r1".to_string(),
            operation: "unknown".to_string(),
            execute_fn: None,
            included: std::collections::HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        };
        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_abandon_not_found() {
        let h = make_handler();
        let ctx = HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: make_execute(),
            params: make_params(entity_ecf::Value::Null),
            pattern: format!("/{}/system/continuation", test_peer_id()),
            suffix: String::new(),
            resource_target: Some(entity_capability::ResourceTarget {
                targets: vec!["cont/test".to_string()],
                exclude: vec![],
            }),
            author: None,
            session_peer_id: None,
            request_id: "r1".to_string(),
            operation: "abandon".to_string(),
            execute_fn: None,
            included: std::collections::HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        };
        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_abandon_suspended() {
        let h = make_handler();

        // Store a suspended entity
        let suspended_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("target"), entity_ecf::text("app/handler")),
            (entity_ecf::text("operation"), entity_ecf::text("process")),
        ]));
        let suspended = Entity::new("system/continuation/suspended", suspended_data).unwrap();
        let hash = h.content_store.put(suspended).unwrap();
        h.location_index.set("cont/test", hash);

        let ctx = HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: make_execute(),
            params: make_params(entity_ecf::Value::Null),
            pattern: format!("/{}/system/continuation", test_peer_id()),
            suffix: String::new(),
            resource_target: Some(entity_capability::ResourceTarget {
                targets: vec!["cont/test".to_string()],
                exclude: vec![],
            }),
            author: None,
            session_peer_id: None,
            request_id: "r1".to_string(),
            operation: "abandon".to_string(),
            execute_fn: None,
            included: std::collections::HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        };
        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let abandoned = map.iter().find(|(k, _)| k.as_text() == Some("abandoned")).unwrap();
        assert_eq!(abandoned.1.as_bool(), Some(true));

        // Entity should be removed
        assert!(h.location_index.get("cont/test").is_none());
    }

    #[test]
    fn test_assemble_passthrough() {
        let result = vec![1, 2, 3];
        let assembled = assemble_params(&None, &None, &result).unwrap();
        assert_eq!(assembled, result);
    }

    #[test]
    fn test_assemble_trigger() {
        let params = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("key"), entity_ecf::text("val")),
        ]));
        let result = vec![1, 2, 3];
        let assembled = assemble_params(&Some(params.clone()), &None, &result).unwrap();
        assert_eq!(assembled, params);
    }

    #[test]
    fn test_assemble_inject() {
        let params = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("x"), entity_ecf::text("y")),
        ]));
        let result_bytes = {
            let mut buf = Vec::new();
            ciborium::into_writer(&ciborium::Value::Text("injected".into()), &mut buf).unwrap();
            buf
        };
        let assembled = assemble_params(&Some(params), &Some("data".into()), &result_bytes).unwrap();
        let val: ciborium::Value = ciborium::from_reader(assembled.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        assert_eq!(map.len(), 2); // x + data
    }

    #[test]
    fn test_assemble_result_field_without_params_is_error() {
        let result = vec![1, 2, 3];
        let err = assemble_params(&None, &Some("field".into()), &result);
        assert!(err.is_err());
    }

    #[test]
    fn test_navigate_opt() {
        let val = ciborium::Value::Map(vec![(
            ciborium::Value::Text("a".into()),
            ciborium::Value::Map(vec![(
                ciborium::Value::Text("b".into()),
                ciborium::Value::Text("found".into()),
            )]),
        )]);
        // Hit.
        assert_eq!(
            navigate_opt(&val, "a.b").and_then(|v| v.as_text().map(String::from)),
            Some("found".to_string())
        );
        // §2.2 best-effort: miss ⇒ None, never an error.
        assert_eq!(navigate_opt(&val, "a.missing"), None);
        assert_eq!(navigate_opt(&val, "x"), None);
        // Not a map at a segment ⇒ None.
        assert_eq!(navigate_opt(&val, "a.b.c"), None);
    }

    // -------------------------------------------------------------------
    // v1.9: transform pipeline (§2.2/§3.6), transform_ops (G1),
    // *_extract resolution (v1.7), install fail-closed (§8.1).
    // -------------------------------------------------------------------

    fn cbor(v: ciborium::Value) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(&v, &mut b).unwrap();
        b
    }
    fn decode(b: &[u8]) -> ciborium::Value {
        ciborium::from_reader(b).unwrap()
    }
    fn txt(s: &str) -> ciborium::Value {
        ciborium::Value::Text(s.into())
    }
    fn op(name: &str) -> TransformOp {
        TransformOp {
            op: name.into(),
            field: None,
            into: None,
            fields: None,
            prefix: None,
            literal: None,
            from: None,
            to: None,
            sep: None,
            range: None,
        }
    }
    fn td() -> TransformData {
        TransformData {
            extract: None,
            select: None,
            transform_ops: Vec::new(),
            resource_extract: None,
            target_extract: None,
            operation_extract: None,
        }
    }

    #[test]
    fn test_pipeline_extract_then_select_sequential() {
        // Pre-v1.9 bug: extract early-returned so select never ran when
        // both were present. §2.2: extract first, select on the result.
        let input = cbor(ciborium::Value::Map(vec![(
            txt("outer"),
            ciborium::Value::Map(vec![(txt("a"), txt("v")), (txt("b"), txt("w"))]),
        )]));
        let mut t = td();
        t.extract = Some("outer".into());
        let mut sel = HashMap::new();
        sel.insert("x".to_string(), "a".to_string());
        t.select = Some(sel);
        let out = decode(&apply_transform(&input, &Some(t), &HashMap::new()).unwrap());
        let m = out.as_map().unwrap();
        assert_eq!(
            m.iter().find(|(k, _)| k.as_text() == Some("x")).unwrap().1.as_text(),
            Some("v")
        );
    }

    #[test]
    fn test_pipeline_best_effort_passthrough() {
        // §2.2: extract miss ⇒ original unmodified result passes through.
        let input = cbor(ciborium::Value::Map(vec![(txt("k"), txt("orig"))]));
        let mut t = td();
        t.extract = Some("does.not.exist".into());
        let out = decode(&apply_transform(&input, &Some(t), &HashMap::new()).unwrap());
        assert_eq!(
            out.as_map()
                .unwrap()
                .iter()
                .find(|(k, _)| k.as_text() == Some("k"))
                .unwrap()
                .1
                .as_text(),
            Some("orig")
        );
        // §2.2: undecodable result ⇒ original bytes through, no error.
        let bad = vec![0xff, 0xff, 0xff];
        let mut t2 = td();
        t2.extract = Some("a".into());
        assert_eq!(apply_transform(&bad, &Some(t2), &HashMap::new()).unwrap(), bad);
    }

    #[test]
    fn test_transform_ops_all_seven() {
        let base = || {
            ciborium::Value::Map(vec![
                (txt("p"), txt("/peer/system/tree/notes/x")),
                (txt("a"), txt("foo")),
                (txt("b"), txt("bar")),
            ])
        };
        let inc: HashMap<Hash, Entity> = HashMap::new();
        let run = |o: TransformOp| apply_transform_op(base(), &o, &inc);
        let get = |v: &ciborium::Value, k: &str| {
            v.as_map()
                .unwrap()
                .iter()
                .find(|(kk, _)| kk.as_text() == Some(k))
                .map(|(_, vv)| vv.clone())
        };

        // strip_prefix
        let o = TransformOp { field: Some("p".into()), prefix: Some("/peer/system/tree".into()), ..op("strip_prefix") };
        assert_eq!(get(&run(o), "p").unwrap().as_text(), Some("/notes/x"));
        // prepend / append
        let o = TransformOp { field: Some("a".into()), literal: Some("X-".into()), ..op("prepend") };
        assert_eq!(get(&run(o), "a").unwrap().as_text(), Some("X-foo"));
        let o = TransformOp { field: Some("a".into()), literal: Some("-Y".into()), ..op("append") };
        assert_eq!(get(&run(o), "a").unwrap().as_text(), Some("foo-Y"));
        // join
        let o = TransformOp { fields: Some(vec!["a".into(), "b".into()]), sep: Some("/".into()), into: Some("c".into()), ..op("join") };
        assert_eq!(get(&run(o), "c").unwrap().as_text(), Some("foo/bar"));
        // replace_literal
        let o = TransformOp { field: Some("a".into()), from: Some("o".into()), to: Some("0".into()), ..op("replace_literal") };
        assert_eq!(get(&run(o), "a").unwrap().as_text(), Some("f00"));
        // split
        let o = TransformOp { field: Some("p".into()), sep: Some("/".into()), into: Some("parts".into()), ..op("split") };
        let parts = get(&run(o), "parts").unwrap();
        assert_eq!(parts.as_array().unwrap().len(), 6); // leading "" + 5 segs
        // slice (chars 1..5 of "foo" → clamp)
        let o = TransformOp { field: Some("a".into()), range: Some("1:2".into()), into: Some("s".into()), ..op("slice") };
        assert_eq!(get(&run(o), "s").unwrap().as_text(), Some("o"));

        // Totality: missing field ⇒ no-op (value unchanged, no panic).
        let o = TransformOp { field: Some("absent".into()), prefix: Some("z".into()), ..op("strip_prefix") };
        assert_eq!(get(&run(o), "a").unwrap().as_text(), Some("foo"));
        // Totality: non-map value ⇒ returned unchanged.
        let nm = apply_transform_op(txt("scalar"), &op("prepend"), &HashMap::new());
        assert_eq!(nm.as_text(), Some("scalar"));
    }

    #[test]
    fn test_pipeline_ops_after_extract_select() {
        // §2.2 order: extract → select → transform_ops.
        let input = cbor(ciborium::Value::Map(vec![(
            txt("r"),
            ciborium::Value::Map(vec![(txt("path"), txt("/a/b/c"))]),
        )]));
        let mut t = td();
        t.extract = Some("r".into());
        t.transform_ops = vec![TransformOp {
            field: Some("path".into()),
            prefix: Some("/a/b".into()),
            ..op("strip_prefix")
        }];
        let out = decode(&apply_transform(&input, &Some(t), &HashMap::new()).unwrap());
        assert_eq!(
            out.as_map().unwrap().iter().find(|(k, _)| k.as_text() == Some("path")).unwrap().1.as_text(),
            Some("/c")
        );
    }

    #[test]
    fn test_deref_included_replaces_hash_with_entity() {
        // EXTENSION-CONTINUATION v1.17 §2.2: field carrying a system/hash that
        // resolves in envelope.included is replaced with the inline entity
        // {type, data, content_hash} so downstream extract / assemble_params
        // can splice it without a handler step.
        let entity = Entity::new("app/payload", b"v17-bytes".to_vec()).unwrap();
        let h = entity.content_hash;
        let mut inc: HashMap<Hash, Entity> = HashMap::new();
        inc.insert(h, entity.clone());

        let v = ciborium::Value::Map(vec![(
            txt("ref"),
            ciborium::Value::Bytes(h.to_bytes().to_vec()),
        )]);
        let out = apply_transform_op(
            v,
            &TransformOp {
                field: Some("ref".into()),
                ..op("deref_included")
            },
            &inc,
        );
        let m = out.as_map().unwrap();
        let inline = m
            .iter()
            .find(|(k, _)| k.as_text() == Some("ref"))
            .map(|(_, v)| v.clone())
            .unwrap();
        let inline_m = inline.as_map().unwrap();
        let ty = inline_m
            .iter()
            .find(|(k, _)| k.as_text() == Some("type"))
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(ty.as_text(), Some("app/payload"));
        let inline_hash = inline_m
            .iter()
            .find(|(k, _)| k.as_text() == Some("content_hash"))
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(inline_hash.as_bytes().unwrap().as_slice(), h.to_bytes().as_slice());
    }

    #[test]
    fn test_deref_included_total_no_ops() {
        // §2.2 totality: each best-effort condition is a no-op (value
        // unchanged), not an error.
        let inc: HashMap<Hash, Entity> = HashMap::new();
        let bytes = vec![0xff, 0xff];
        let cases = vec![
            // 1. field missing from the map
            (
                ciborium::Value::Map(vec![(txt("other"), txt("x"))]),
                TransformOp {
                    field: Some("missing".into()),
                    ..op("deref_included")
                },
            ),
            // 2. field present but not bytes
            (
                ciborium::Value::Map(vec![(txt("ref"), txt("not bytes"))]),
                TransformOp {
                    field: Some("ref".into()),
                    ..op("deref_included")
                },
            ),
            // 3. field is bytes but Hash::from_bytes fails (too short)
            (
                ciborium::Value::Map(vec![(txt("ref"), ciborium::Value::Bytes(bytes.clone()))]),
                TransformOp {
                    field: Some("ref".into()),
                    ..op("deref_included")
                },
            ),
        ];
        for (input, op) in cases {
            let original = input.clone();
            let out = apply_transform_op(input, &op, &inc);
            assert_eq!(out, original, "deref_included must be a no-op for {:?}", op.field);
        }

        // 4. valid hash, but absent from included → no-op (value unchanged).
        let absent_hash = Hash::compute("test", b"absent");
        let v = ciborium::Value::Map(vec![(
            txt("ref"),
            ciborium::Value::Bytes(absent_hash.to_bytes().to_vec()),
        )]);
        let original = v.clone();
        let out = apply_transform_op(
            v,
            &TransformOp {
                field: Some("ref".into()),
                ..op("deref_included")
            },
            &inc,
        );
        assert_eq!(out, original);
    }

    /// Cross-impl conformance regression (validator): full
    /// install + advance round where `deref_included` is configured but the
    /// hash resolves to no entity (empty `ctx.included` at advance). The
    /// §2.2 best-effort rule pins this as a NO-OP — advance MUST still
    /// return 200 ({advanced:true}), not 400.
    #[tokio::test]
    async fn test_deref_included_miss_advance_returns_200() {
        let h = make_handler();
        let author = Hash::compute("test", b"deref-miss-author");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let install_included: HashMap<Hash, Entity> =
            [(cap_hash, cap.clone())].into();

        // Build install params with a result_transform that derefs `ref`.
        let path = format!(
            "/{}/system/continuation/suspended/deref-miss",
            test_peer_id()
        );
        let install_params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("process")),
            (entity_ecf::text("target"), entity_ecf::text("app/sink")),
            (
                entity_ecf::text("dispatch_capability"),
                entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("result_transform"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("transform_ops"),
                    entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                        (entity_ecf::text("op"), entity_ecf::text("deref_included")),
                        (entity_ecf::text("field"), entity_ecf::text("ref")),
                    ])]),
                )]),
            ),
        ]));
        let install_params =
            Entity::new(entity_types::TYPE_CONTINUATION, install_params_data).unwrap();
        let install_ctx = make_install_ctx(author, &path, install_params, install_included);
        assert_eq!(h.handle(&install_ctx).await.unwrap().status, STATUS_OK);

        // Mock sink — 200 OK regardless of params.
        let mock: ExecuteFn = Arc::new(|_uri, _op, _params, _opts| {
            Box::pin(async {
                Ok(HandlerResult {
                    status: 200,
                    result: Entity::new(
                        "primitive/null",
                        entity_ecf::to_ecf(&entity_ecf::Value::Null),
                    )
                    .unwrap(),
                    included: HashMap::new(),
                })
            })
        });

        // Advance with a hash-shaped bytes field that is NOT in included.
        let phantom = Hash::compute("test", b"phantom-not-in-included");
        let result_inner = entity_ecf::Value::Map(vec![(
            entity_ecf::text("ref"),
            entity_ecf::Value::Bytes(phantom.to_bytes().to_vec()),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&result_inner, &mut buf).unwrap();
        let adv_params = make_params(entity_ecf::Value::Map(vec![(
            entity_ecf::text("result"),
            entity_ecf::Value::Bytes(buf),
        )]));
        // Empty included at advance → deref_included must no-op.
        let mut adv_ctx = make_install_ctx(author, &path, adv_params, HashMap::new());
        adv_ctx.operation = "advance".to_string();
        adv_ctx.execute_fn = Some(mock);

        let r = h.handle(&adv_ctx).await.unwrap();
        assert_eq!(
            r.status, STATUS_OK,
            "deref_included miss MUST be a no-op (§2.2); advance must NOT return 400"
        );
    }

    /// Variant: result has no `ref` field at all (field missing from the map).
    /// Still a §2.2 no-op.
    #[tokio::test]
    async fn test_deref_included_miss_field_missing_returns_200() {
        let h = make_handler();
        let author = Hash::compute("test", b"deref-miss-field-author");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let install_included: HashMap<Hash, Entity> =
            [(cap_hash, cap.clone())].into();

        let path = format!(
            "/{}/system/continuation/suspended/deref-miss-field",
            test_peer_id()
        );
        let install_params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("process")),
            (entity_ecf::text("target"), entity_ecf::text("app/sink")),
            (
                entity_ecf::text("dispatch_capability"),
                entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("result_transform"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("transform_ops"),
                    entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                        (entity_ecf::text("op"), entity_ecf::text("deref_included")),
                        (entity_ecf::text("field"), entity_ecf::text("ref")),
                    ])]),
                )]),
            ),
        ]));
        let install_params =
            Entity::new(entity_types::TYPE_CONTINUATION, install_params_data).unwrap();
        let install_ctx = make_install_ctx(author, &path, install_params, install_included);
        assert_eq!(h.handle(&install_ctx).await.unwrap().status, STATUS_OK);

        let mock: ExecuteFn = Arc::new(|_uri, _op, _params, _opts| {
            Box::pin(async {
                Ok(HandlerResult {
                    status: 200,
                    result: Entity::new(
                        "primitive/null",
                        entity_ecf::to_ecf(&entity_ecf::Value::Null),
                    )
                    .unwrap(),
                    included: HashMap::new(),
                })
            })
        });

        // Result is a map but doesn't have `ref` at all.
        let result_inner = entity_ecf::Value::Map(vec![(
            entity_ecf::text("other"),
            entity_ecf::text("data"),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&result_inner, &mut buf).unwrap();
        let adv_params = make_params(entity_ecf::Value::Map(vec![(
            entity_ecf::text("result"),
            entity_ecf::Value::Bytes(buf),
        )]));
        let mut adv_ctx = make_install_ctx(author, &path, adv_params, HashMap::new());
        adv_ctx.operation = "advance".to_string();
        adv_ctx.execute_fn = Some(mock);

        let r = h.handle(&adv_ctx).await.unwrap();
        assert_eq!(r.status, STATUS_OK, "missing field MUST be no-op");
    }

    /// Variant: validator likely passes the advance `result` as a raw map
    /// (not bytes-wrapped). Replicates the wire shape Go/Python use.
    #[tokio::test]
    async fn test_deref_included_miss_result_as_map_returns_200() {
        let h = make_handler();
        let author = Hash::compute("test", b"deref-miss-map-author");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let install_included: HashMap<Hash, Entity> =
            [(cap_hash, cap.clone())].into();

        let path = format!(
            "/{}/system/continuation/suspended/deref-miss-map",
            test_peer_id()
        );
        let install_params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("process")),
            (entity_ecf::text("target"), entity_ecf::text("app/sink")),
            (
                entity_ecf::text("dispatch_capability"),
                entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("result_transform"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("transform_ops"),
                    entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                        (entity_ecf::text("op"), entity_ecf::text("deref_included")),
                        (entity_ecf::text("field"), entity_ecf::text("ref")),
                    ])]),
                )]),
            ),
        ]));
        let install_params =
            Entity::new(entity_types::TYPE_CONTINUATION, install_params_data).unwrap();
        let install_ctx = make_install_ctx(author, &path, install_params, install_included);
        assert_eq!(h.handle(&install_ctx).await.unwrap().status, STATUS_OK);

        let mock: ExecuteFn = Arc::new(|_uri, _op, _params, _opts| {
            Box::pin(async {
                Ok(HandlerResult {
                    status: 200,
                    result: Entity::new(
                        "primitive/null",
                        entity_ecf::to_ecf(&entity_ecf::Value::Null),
                    )
                    .unwrap(),
                    included: HashMap::new(),
                })
            })
        });

        // result is a raw CBOR map (not bytes-encoded). decode_advance_request
        // handles this branch.
        let phantom = Hash::compute("test", b"phantom-2");
        let adv_params = make_params(entity_ecf::Value::Map(vec![(
            entity_ecf::text("result"),
            entity_ecf::Value::Map(vec![(
                entity_ecf::text("ref"),
                entity_ecf::Value::Bytes(phantom.to_bytes().to_vec()),
            )]),
        )]));
        let mut adv_ctx = make_install_ctx(author, &path, adv_params, HashMap::new());
        adv_ctx.operation = "advance".to_string();
        adv_ctx.execute_fn = Some(mock);

        let r = h.handle(&adv_ctx).await.unwrap();
        assert_eq!(
            r.status, STATUS_OK,
            "deref_included miss with raw-map result MUST be no-op"
        );
    }

    /// Cross-impl validator's exact shape (continuations.go
    /// `deref_included_miss_noop` 1603-1654): continuation with
    /// `select{"entity":"hash"}` + `transform_ops{deref_included, field:"entity"}`,
    /// target=tree:put, advance result is `{"hash": <some_hash>}`, included
    /// empty. Advance MUST return wire status 200 — the deref miss is a
    /// §2.2 no-op and even though the downstream tree:put trips on the
    /// unresolved bytes, that's a handler-level non-2xx, not a propagated
    /// Err (v1.10 §3.4).
    #[tokio::test]
    async fn test_deref_included_miss_validator_recipe_returns_200() {
        let h = make_handler();
        let author = Hash::compute("test", b"validator-recipe-author");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let install_included: HashMap<Hash, Entity> =
            [(cap_hash, cap.clone())].into();

        let path = format!(
            "/{}/system/continuation/suspended/validator-recipe",
            test_peer_id()
        );
        let install_params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("put")),
            (entity_ecf::text("target"), entity_ecf::text("system/tree")),
            (
                entity_ecf::text("dispatch_capability"),
                entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("resource"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("targets"),
                    entity_ecf::Value::Array(vec![entity_ecf::text(
                        "system/validate/deref/miss/target",
                    )]),
                )]),
            ),
            (
                entity_ecf::text("result_transform"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("select"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("entity"),
                            entity_ecf::text("hash"),
                        )]),
                    ),
                    (
                        entity_ecf::text("transform_ops"),
                        entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                            (entity_ecf::text("op"), entity_ecf::text("deref_included")),
                            (entity_ecf::text("field"), entity_ecf::text("entity")),
                        ])]),
                    ),
                ]),
            ),
        ]));
        let install_params =
            Entity::new(entity_types::TYPE_CONTINUATION, install_params_data).unwrap();
        let install_ctx = make_install_ctx(author, &path, install_params, install_included);
        assert_eq!(h.handle(&install_ctx).await.unwrap().status, STATUS_OK);

        // Mock tree:put that mirrors production: returns Err(InvalidParams)
        // when entity is bytes-not-map (decode_entity_from_cbor failure).
        // The advance MUST still return 200 — the spec pins handler-level
        // errors as completed-dispatch, not propagated Err.
        let mock: ExecuteFn = Arc::new(|_uri, _op, _params, _opts| {
            Box::pin(async {
                Err(HandlerError::InvalidParams(
                    "invalid_entity: bytes not a map".into(),
                ))
            })
        });

        let phantom = Hash::compute("test", b"validator-phantom");
        let adv_params = make_params(entity_ecf::Value::Map(vec![(
            entity_ecf::text("result"),
            entity_ecf::Value::Map(vec![(
                entity_ecf::text("hash"),
                entity_ecf::Value::Bytes(phantom.to_bytes().to_vec()),
            )]),
        )]));
        let mut adv_ctx = make_install_ctx(author, &path, adv_params, HashMap::new());
        adv_ctx.operation = "advance".to_string();
        adv_ctx.execute_fn = Some(mock);

        let r = h.handle(&adv_ctx).await;
        match r {
            Ok(res) => assert_eq!(
                res.status, STATUS_OK,
                "deref_included miss MUST yield advance status 200, even when downstream handler fails (v1.10 §3.4 + v1.17 §2.2)"
            ),
            Err(e) => panic!(
                "advance returned Err({e:?}) — handler-level non-2xx must NOT propagate as Err (v1.10 §3.4)"
            ),
        }
    }

    #[test]
    fn test_deref_included_registered_in_known_ops() {
        // §8.1 fail-closed: deref_included MUST be in KNOWN_TRANSFORM_OPS so
        // install accepts it. Unknown ops are rejected at install time.
        assert!(KNOWN_TRANSFORM_OPS.contains(&"deref_included"));
        let mut t = td();
        t.transform_ops = vec![TransformOp {
            field: Some("ref".into()),
            ..op("deref_included")
        }];
        assert!(validate_transform_ops(&Some(t)).is_ok());
    }

    #[test]
    fn test_validate_transform_ops_fail_closed() {
        let mut t = td();
        t.transform_ops = vec![op("strip_prefix"), op("join")];
        assert!(validate_transform_ops(&Some(t)).is_ok());
        let mut bad = td();
        bad.transform_ops = vec![op("strip_prefix"), op("eval_arbitrary")];
        match validate_transform_ops(&Some(bad)).unwrap_err() {
            TransformOpsError::UnknownOp(name) => assert_eq!(name, "eval_arbitrary"),
            _ => panic!("expected UnknownOp"),
        }
        assert!(validate_transform_ops(&None).is_ok());
    }

    #[test]
    fn test_collect_keys_singular_and_plural() {
        // EXTENSION-CONTINUATION v1.15 §2.2: collect_keys{field} singular
        // projects one map's keys; collect_keys{fields:[...]} plural
        // concatenates in list order. Field navigation follows the dotted-path
        // rules from `extract`.
        let base = || {
            ciborium::Value::Map(vec![
                (
                    txt("added"),
                    ciborium::Value::Map(vec![
                        (txt("notes/a"), txt("h1")),
                        (txt("notes/b"), txt("h2")),
                    ]),
                ),
                (
                    txt("changed"),
                    ciborium::Value::Map(vec![(txt("notes/c"), txt("h3"))]),
                ),
            ])
        };
        let get = |v: &ciborium::Value, k: &str| {
            v.as_map()
                .unwrap()
                .iter()
                .find(|(kk, _)| kk.as_text() == Some(k))
                .map(|(_, vv)| vv.clone())
        };

        // Singular: projects `added` keys.
        let o = TransformOp {
            field: Some("added".into()),
            into: Some("paths".into()),
            ..op("collect_keys")
        };
        let out = apply_transform_op(base(), &o, &HashMap::new());
        let paths = get(&out, "paths").unwrap();
        let arr = paths.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        let texts: Vec<&str> = arr.iter().filter_map(|v| v.as_text()).collect();
        assert!(texts.contains(&"notes/a"));
        assert!(texts.contains(&"notes/b"));

        // Plural: concatenates added ∪ changed keys (in list order).
        let o = TransformOp {
            fields: Some(vec!["added".into(), "changed".into()]),
            into: Some("paths".into()),
            ..op("collect_keys")
        };
        let out = apply_transform_op(base(), &o, &HashMap::new());
        let paths = get(&out, "paths").unwrap();
        let arr = paths.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        let texts: Vec<&str> = arr.iter().filter_map(|v| v.as_text()).collect();
        assert!(texts.contains(&"notes/a"));
        assert!(texts.contains(&"notes/b"));
        assert!(texts.contains(&"notes/c"));
    }

    #[test]
    fn test_collect_keys_totality() {
        // §2.2 best-effort rules:
        // - Empty source map → write empty array.
        // - Singular form, missing or non-map source → no-op (no write).
        // - Plural form, all sources missing → write empty array (the
        //   concatenation of zero maps is the empty array).
        // - Empty/absent `into` → silent no-op (no write).
        let base = || {
            ciborium::Value::Map(vec![
                (txt("empty"), ciborium::Value::Map(vec![])),
                (txt("scalar"), txt("not-a-map")),
            ])
        };
        let get = |v: &ciborium::Value, k: &str| {
            v.as_map()
                .unwrap()
                .iter()
                .find(|(kk, _)| kk.as_text() == Some(k))
                .map(|(_, vv)| vv.clone())
        };

        // Empty map source → empty array written.
        let o = TransformOp {
            field: Some("empty".into()),
            into: Some("paths".into()),
            ..op("collect_keys")
        };
        let out = apply_transform_op(base(), &o, &HashMap::new());
        assert_eq!(get(&out, "paths").unwrap().as_array().unwrap().len(), 0);

        // Singular, non-map source → no-op (no write of `paths`).
        let o = TransformOp {
            field: Some("scalar".into()),
            into: Some("paths".into()),
            ..op("collect_keys")
        };
        let out = apply_transform_op(base(), &o, &HashMap::new());
        assert!(get(&out, "paths").is_none());

        // Singular, missing field → no-op.
        let o = TransformOp {
            field: Some("does-not-exist".into()),
            into: Some("paths".into()),
            ..op("collect_keys")
        };
        let out = apply_transform_op(base(), &o, &HashMap::new());
        assert!(get(&out, "paths").is_none());

        // Plural, all entries missing → empty array written (concatenation
        // of zero contributing maps).
        let o = TransformOp {
            fields: Some(vec!["nope-a".into(), "nope-b".into()]),
            into: Some("paths".into()),
            ..op("collect_keys")
        };
        let out = apply_transform_op(base(), &o, &HashMap::new());
        assert_eq!(get(&out, "paths").unwrap().as_array().unwrap().len(), 0);

        // Empty `into` → silent no-op (no write).
        let o = TransformOp {
            field: Some("empty".into()),
            into: Some(String::new()),
            ..op("collect_keys")
        };
        let out = apply_transform_op(base(), &o, &HashMap::new());
        assert!(get(&out, "paths").is_none());

        // `into` absent → silent no-op.
        let o = TransformOp {
            field: Some("empty".into()),
            into: None,
            ..op("collect_keys")
        };
        let out = apply_transform_op(base(), &o, &HashMap::new());
        assert!(get(&out, "paths").is_none());
    }

    #[test]
    fn test_collect_keys_dotted_path_navigation() {
        // §2.2: `field` and entries in `fields` follow the dotted-path rules
        // from `extract`. Navigate into a nested map.
        let v = ciborium::Value::Map(vec![(
            txt("data"),
            ciborium::Value::Map(vec![(
                txt("added"),
                ciborium::Value::Map(vec![(txt("x"), txt("h1")), (txt("y"), txt("h2"))]),
            )]),
        )]);
        let o = TransformOp {
            field: Some("data.added".into()),
            into: Some("paths".into()),
            ..op("collect_keys")
        };
        let out = apply_transform_op(v, &o, &HashMap::new());
        let paths = out
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("paths"))
            .unwrap()
            .1
            .clone();
        let arr = paths.as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_collect_keys_mutual_exclusivity_rejects_at_install() {
        // §2.2 v1.15: a single `collect_keys` op MUST NOT carry both `field`
        // and `fields`. Install MUST reject with `400 invalid_transform_args`.
        let mut t = td();
        t.transform_ops = vec![TransformOp {
            op: "collect_keys".into(),
            field: Some("added".into()),
            fields: Some(vec!["changed".into()]),
            into: Some("paths".into()),
            ..op("collect_keys")
        }];
        match validate_transform_ops(&Some(t)).unwrap_err() {
            TransformOpsError::InvalidArgs(msg) => {
                assert!(msg.contains("mutually exclusive"), "msg: {msg}");
            }
            _ => panic!("expected InvalidArgs"),
        }
    }

    #[test]
    fn test_collect_keys_is_known_op() {
        // §2.2 v1.15: `collect_keys` must be in the recognized op set so it
        // is not rejected with `400 unknown_transform_op`.
        assert!(KNOWN_TRANSFORM_OPS.contains(&"collect_keys"));
        let mut t = td();
        t.transform_ops = vec![TransformOp {
            op: "collect_keys".into(),
            field: Some("added".into()),
            into: Some("paths".into()),
            ..op("collect_keys")
        }];
        assert!(validate_transform_ops(&Some(t)).is_ok());
    }

    #[test]
    fn test_resolve_or_default() {
        let v = ciborium::Value::Map(vec![(txt("t"), txt("/peer/handler"))]);
        // None path ⇒ static default.
        assert_eq!(resolve_or_default(&v, &None, "STATIC"), "STATIC");
        // Resolves ⇒ extracted.
        assert_eq!(
            resolve_or_default(&v, &Some("t".into()), "STATIC"),
            "/peer/handler"
        );
        // Miss ⇒ static default.
        assert_eq!(
            resolve_or_default(&v, &Some("nope".into()), "STATIC"),
            "STATIC"
        );
    }

    #[test]
    fn test_resolve_or_default_resource() {
        let dflt = Some(entity_capability::ResourceTarget {
            targets: vec!["/static".into()],
            exclude: Vec::new(),
        });
        // string ⇒ {targets:[s]}
        let v = ciborium::Value::Map(vec![(txt("u"), txt("/dyn/path"))]);
        let r = resolve_or_default_resource(&v, &Some("u".into()), &dflt).unwrap();
        assert_eq!(r.targets, vec!["/dyn/path".to_string()]);
        // array ⇒ {targets: arr}
        let v = ciborium::Value::Map(vec![(
            txt("u"),
            ciborium::Value::Array(vec![txt("/a"), txt("/b")]),
        )]);
        let r = resolve_or_default_resource(&v, &Some("u".into()), &dflt).unwrap();
        assert_eq!(r.targets, vec!["/a".to_string(), "/b".to_string()]);
        // None path / miss ⇒ default.
        assert_eq!(
            resolve_or_default_resource(&v, &None, &dflt).unwrap().targets,
            vec!["/static".to_string()]
        );
        assert_eq!(
            resolve_or_default_resource(&v, &Some("miss".into()), &dflt)
                .unwrap()
                .targets,
            vec!["/static".to_string()]
        );
    }

    #[tokio::test]
    async fn test_v1_10_forward_dispatch_non_2xx_is_completed_not_promoted() {
        // EXTENSION-CONTINUATION v1.10 §3.4 (forward-dispatch outcome
        // classification, normative): a *delivered* EXECUTE returning a
        // handler-level non-2xx is a COMPLETED forward dispatch (forward is
        // fire-and-forget — closure invocation, not RPC). It MUST advance
        // ({advanced:true}) and MUST NOT be promoted to transient/permanent
        // (no suspend, no error status). `dispatch_result.error` is a
        // dispatch *delivery/processing* failure only (the execute_fn `Err`
        // arm). Regression guard: the spec pinned to the reference impl's
        // existing behavior precisely so impls don't drift — this fails if
        // anyone later adds status-promotion logic to advance_forward.
        let h = make_handler();
        let author = Hash::compute("test", b"v110-author");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let included: HashMap<Hash, Entity> = [(cap_hash, cap.clone())].into();

        // Install a forward continuation through the real install op so the
        // cap + chain land in the content store (matches production path).
        let path = format!("/{}/system/continuation/suspended/v110", test_peer_id());
        let install_params =
            make_install_params("app/target", "process", cap_hash, None, None);
        let install_ctx = make_install_ctx(author, &path, install_params, included);
        assert_eq!(h.handle(&install_ctx).await.unwrap().status, STATUS_OK);

        // The dispatched EXECUTE is delivered; the target handler returns a
        // handler-level 403 as `Ok` (NOT an execute_fn `Err`).
        let mock: ExecuteFn = Arc::new(|_uri, _op, _params, _opts| {
            Box::pin(async {
                Ok(HandlerResult {
                    status: 403,
                    result: Entity::new(
                        "primitive/null",
                        entity_ecf::to_ecf(&entity_ecf::Value::Null),
                    )
                    .unwrap(),
                    included: HashMap::new(),
                })
            })
        });

        // Inbound advance is a success (no `status` ⇒ 200 ⇒ not the
        // inbound-error on_error path; this isolates the §3.4 dispatch
        // outcome).
        let adv_params = make_params(entity_ecf::Value::Map(vec![(
            entity_ecf::text("result"),
            entity_ecf::Value::Map(vec![(entity_ecf::text("k"), entity_ecf::text("v"))]),
        )]));
        let mut adv_ctx = make_install_ctx(author, &path, adv_params, HashMap::new());
        adv_ctx.operation = "advance".to_string();
        adv_ctx.execute_fn = Some(mock);

        let r = h.handle(&adv_ctx).await.unwrap();

        // Completed forward dispatch: 200 + {advanced:true}; NOT promoted.
        assert_eq!(
            r.status, STATUS_OK,
            "delivered non-2xx MUST NOT become an error status (v1.10 §3.4)"
        );
        let v: ciborium::Value = ciborium::from_reader(r.result.data.as_slice()).unwrap();
        let m = v.as_map().unwrap();
        let get = |k: &str| {
            m.iter()
                .find(|(kk, _)| kk.as_text() == Some(k))
                .map(|(_, vv)| vv.clone())
        };
        assert_eq!(
            get("advanced").and_then(|x| x.as_bool()),
            Some(true),
            "delivered non-2xx is a completed forward dispatch — MUST advance"
        );
        assert!(
            get("suspended").and_then(|x| x.as_bool()) != Some(true),
            "delivered non-2xx MUST NOT be promoted to suspended (v1.10 §3.4)"
        );
    }

    #[test]
    fn test_advancement_result() {
        let result = advancement_result(true);
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let advanced = map.iter().find(|(k, _)| k.as_text() == Some("advanced")).unwrap();
        assert_eq!(advanced.1.as_bool(), Some(true));
    }

    // -------------------------------------------------------------------
    // CT1-CT2 — install operation + R1 chain-root check
    // (PROPOSAL-COHERENT-CAPABILITY-AUTHORITY, EXTENSION-CONTINUATION §3.2)
    // -------------------------------------------------------------------

    fn make_cap_entity_for_install(
        granter: Hash,
        grantee: Hash,
        parent: Option<Hash>,
    ) -> Entity {
        let mut fields = vec![
            (entity_ecf::text("created_at"), entity_ecf::integer(0)),
            (
                entity_ecf::text("grantee"),
                entity_ecf::Value::Bytes(grantee.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("granter"),
                entity_ecf::Value::Bytes(granter.to_bytes().to_vec()),
            ),
            (entity_ecf::text("grants"), entity_ecf::Value::Array(vec![])),
        ];
        if let Some(p) = parent {
            fields.push((
                entity_ecf::text("parent"),
                entity_ecf::Value::Bytes(p.to_bytes().to_vec()),
            ));
        }
        Entity::new(
            entity_types::TYPE_CAP_TOKEN,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(fields)),
        )
        .unwrap()
    }

    /// Build a `system/continuation` (kind=None) or `system/continuation/join`
    /// (kind=Some("join")) entity directly. Path moved to resource per
    /// PROPOSAL-PATH-AS-RESOURCE-HYGIENE — no longer carried in params.
    fn make_install_params(
        target: &str,
        operation: &str,
        dispatch_capability: Hash,
        kind: Option<&str>,
        join_inputs: Option<&[&str]>,
    ) -> Entity {
        let is_join = matches!(kind, Some("join"));
        let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = vec![
            (entity_ecf::text("operation"), entity_ecf::text(operation)),
            (entity_ecf::text("target"), entity_ecf::text(target)),
            (
                entity_ecf::text("dispatch_capability"),
                entity_ecf::Value::Bytes(dispatch_capability.to_bytes().to_vec()),
            ),
        ];
        let entity_type = if is_join {
            // Join carries `expected` (the slot list).
            let slots = join_inputs.unwrap_or(&[]);
            let arr: Vec<entity_ecf::Value> = slots.iter().map(|s| entity_ecf::text(*s)).collect();
            fields.push((entity_ecf::text("expected"), entity_ecf::Value::Array(arr)));
            entity_types::TYPE_CONTINUATION_JOIN
        } else {
            entity_types::TYPE_CONTINUATION
        };
        Entity::new(entity_type, entity_ecf::to_ecf(&entity_ecf::Value::Map(fields))).unwrap()
    }

    fn make_install_ctx(
        author: Hash,
        install_path: &str,
        params: Entity,
        included: HashMap<Hash, Entity>,
    ) -> HandlerContext {
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: make_execute(),
            params,
            pattern: format!("/{}/system/continuation", test_peer_id()),
            suffix: String::new(),
            resource_target: Some(entity_capability::ResourceTarget {
                targets: vec![install_path.to_string()],
                exclude: vec![],
            }),
            author: Some(author),
            session_peer_id: None,
            request_id: "r1".to_string(),
            operation: "install".to_string(),
            execute_fn: None,
            included,
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        }
    }

    #[tokio::test]
    async fn test_ct_install_self_issued_succeeds() {
        // Author issues their own dispatch_capability → InChain → 200.
        let h = make_handler();
        let author = Hash::compute("test", b"author-self");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let included: HashMap<Hash, Entity> = [(cap_hash, cap.clone())].into();

        let path = format!("/{}/system/continuation/suspended/c1", test_peer_id());
        let params = make_install_params("app/handler", "process", cap_hash, None, None);
        let ctx = make_install_ctx(author, &path, params, included);

        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK, "install should succeed for self-issued cap");

        // Verify entity persisted at path with correct type.
        let stored_hash = h.location_index.get(&path).expect("path bound");
        let stored = h.content_store.get(&stored_hash).expect("entity stored");
        assert_eq!(stored.entity_type, entity_types::TYPE_CONTINUATION);
    }

    #[tokio::test]
    async fn test_ct_install_foreign_cap_rejected_403() {
        // Adversary embeds admin-issued cap → NotInChain → 403.
        let h = make_handler();
        let admin = Hash::compute("test", b"admin");
        let adversary = Hash::compute("test", b"adversary");
        let admin_cap = make_cap_entity_for_install(admin, admin, None);
        let cap_hash = admin_cap.content_hash;
        let included: HashMap<Hash, Entity> = [(cap_hash, admin_cap.clone())].into();

        let path = format!("/{}/system/continuation/suspended/c1", test_peer_id());
        let params = make_install_params("app/handler", "process", cap_hash, None, None);
        let ctx = make_install_ctx(adversary, &path, params, included);

        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_FORBIDDEN);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let code = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(code, Some("embedded_cap_unauthorized"));

        // Entity must NOT be persisted on rejection.
        assert!(h.location_index.get(&path).is_none());
    }

    #[tokio::test]
    async fn test_ct_install_chain_unreachable_404() {
        // dispatch_capability references a parent not in included or store → 404.
        let h = make_handler();
        let granter = Hash::compute("test", b"granter");
        let grantee = Hash::compute("test", b"grantee");
        let phantom = Hash::compute("test", b"phantom");
        let cap = make_cap_entity_for_install(granter, grantee, Some(phantom));
        let cap_hash = cap.content_hash;
        let included: HashMap<Hash, Entity> = [(cap_hash, cap.clone())].into();

        let path = format!("/{}/system/continuation/suspended/c1", test_peer_id());
        let params = make_install_params("app/handler", "process", cap_hash, None, None);
        // Probe with grantee — walk descends past granter to missing parent.
        let ctx = make_install_ctx(grantee, &path, params, included);

        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_ct_install_missing_dispatch_capability() {
        // Required field not provided → 400 missing_dispatch_capability.
        let h = make_handler();
        let author = Hash::compute("test", b"author");
        let path = format!("/{}/system/continuation/suspended/c1", test_peer_id());
        // system/continuation entity without dispatch_capability set.
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("process")),
            (entity_ecf::text("target"), entity_ecf::text("app/handler")),
        ]));
        let params = Entity::new(entity_types::TYPE_CONTINUATION, params_data).unwrap();
        let ctx = make_install_ctx(author, &path, params, HashMap::new());
        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_ct_install_join_kind_succeeds() {
        // Join continuation: kind="join" + non-empty join_inputs → join entity persisted.
        let h = make_handler();
        let author = Hash::compute("test", b"author");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let included: HashMap<Hash, Entity> = [(cap_hash, cap.clone())].into();

        let path = format!("/{}/system/continuation/suspended/j1", test_peer_id());
        let params = make_install_params(
            "app/aggregator",
            "merge",
            cap_hash,
            Some("join"),
            Some(&["a", "b", "c"]),
        );
        let ctx = make_install_ctx(author, &path, params, included);

        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let stored_hash = h.location_index.get(&path).expect("join path bound");
        let stored = h.content_store.get(&stored_hash).expect("join entity stored");
        assert_eq!(stored.entity_type, entity_types::TYPE_CONTINUATION_JOIN);
    }

    #[tokio::test]
    async fn test_ct_install_leaf_self_issued_with_phantom_parent_404() {
        // Mirror of Go validator vector r1_install_chain_unreachable:
        // adversary submits a leaf cap they signed themselves
        // (granter == author) but with `parent` pointing at a fabricated hash
        // that is absent from envelope and store. R1 must NOT pass — the
        // missing parent makes the chain unwalkable, so the create op MUST
        // return 404 chain_unreachable per PROPOSAL §2 / §8.1.
        let h = make_handler();
        let writer = Hash::compute("test", b"writer-identity");
        let phantom_parent = Hash::compute("test", b"fabricated-admin-cap");
        let leaf = make_cap_entity_for_install(writer, writer, Some(phantom_parent));
        let cap_hash = leaf.content_hash;
        let included: HashMap<Hash, Entity> = [(cap_hash, leaf.clone())].into();

        let path = format!("/{}/system/continuation/suspended/c1", test_peer_id());
        let params = make_install_params("app/handler", "process", cap_hash, None, None);
        let ctx = make_install_ctx(writer, &path, params, included);

        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_NOT_FOUND,
            "leaf-granter-match with phantom parent must yield 404, not 200 — closes Go vector r1_install_chain_unreachable"
        );
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let code = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(code, Some("chain_unreachable"));

        // Entity must NOT be persisted.
        assert!(h.location_index.get(&path).is_none());
    }

    #[tokio::test]
    async fn test_ct_install_uses_resource_target_as_install_key() {
        // Path-as-resource (PROPOSAL-PATH-AS-RESOURCE-HYGIENE P-CONTINUATION-1):
        // dispatch peer-qualifies resource targets before invoking the handler.
        // The handler must persist the continuation at the qualified resource
        // key — same key advance/resume/abandon will look up.
        let h = make_handler();
        let author = Hash::compute("test", b"author");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let included: HashMap<Hash, Entity> = [(cap_hash, cap.clone())].into();

        let qualified = format!("/{}/system/inbox/validate-resource-path", test_peer_id());
        let params = make_install_params("app/handler", "process", cap_hash, None, None);
        let ctx = make_install_ctx(author, &qualified, params, included);

        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        assert!(
            h.location_index.get(&qualified).is_some(),
            "continuation must be persisted at qualified resource key"
        );
    }

    #[tokio::test]
    async fn test_ct_install_intermediate_grant_succeeds() {
        // Chain: root(granter=A,grantee=B), child(granter=B,grantee=C,parent=root).
        // Author = B → matches at child level → InChain → 200.
        let h = make_handler();
        let a = Hash::compute("test", b"identity-A");
        let b = Hash::compute("test", b"identity-B");
        let c = Hash::compute("test", b"identity-C");
        let root = make_cap_entity_for_install(a, b, None);
        let child = make_cap_entity_for_install(b, c, Some(root.content_hash));
        let cap_hash = child.content_hash;
        let included: HashMap<Hash, Entity> = [
            (root.content_hash, root.clone()),
            (cap_hash, child.clone()),
        ]
        .into();

        let path = format!("/{}/system/continuation/suspended/c1", test_peer_id());
        let params = make_install_params("app/handler", "process", cap_hash, None, None);
        let ctx = make_install_ctx(b, &path, params, included);

        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        // Phase: verify cap chain was persisted to content store (root + child).
        assert!(h.content_store.get(&root.content_hash).is_some(),
            "root cap should be persisted");
        assert!(h.content_store.get(&cap_hash).is_some(),
            "leaf cap should be persisted");
    }

    // -------------------------------------------------------------------
    // EXTENSION-CONTINUATION v1.16 — result_merge + per-reason marker path
    // -------------------------------------------------------------------

    /// Build an install-request entity with the given fields. Variant of
    /// `make_install_params` that allows result_merge and result_field.
    fn make_install_params_v116(
        target: &str,
        operation: &str,
        dispatch_capability: Hash,
        static_params: Option<ciborium::Value>,
        result_field: Option<&str>,
        result_merge: bool,
    ) -> Entity {
        let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = vec![
            (entity_ecf::text("operation"), entity_ecf::text(operation)),
            (entity_ecf::text("target"), entity_ecf::text(target)),
            (
                entity_ecf::text("dispatch_capability"),
                entity_ecf::Value::Bytes(dispatch_capability.to_bytes().to_vec()),
            ),
        ];
        if let Some(p) = static_params {
            fields.push((entity_ecf::text("params"), p));
        }
        if let Some(rf) = result_field {
            fields.push((entity_ecf::text("result_field"), entity_ecf::text(rf)));
        }
        if result_merge {
            fields.push((
                entity_ecf::text("result_merge"),
                entity_ecf::bool_val(true),
            ));
        }
        Entity::new(
            entity_types::TYPE_CONTINUATION,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(fields)),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_v116_install_result_merge_accepted() {
        // v1.16 §2.1: result_merge as a standalone field installs cleanly.
        let h = make_handler();
        let author = Hash::compute("test", b"author-rm-1");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let included: HashMap<Hash, Entity> = [(cap_hash, cap.clone())].into();

        let static_params = ciborium::Value::Map(vec![(
            ciborium::Value::Text("scaffold".into()),
            ciborium::Value::Text("static-value".into()),
        )]);

        let path = format!("/{}/system/continuation/suspended/rm-1", test_peer_id());
        let params = make_install_params_v116(
            "app/handler",
            "process",
            cap_hash,
            Some(static_params),
            None,
            true,
        );
        let ctx = make_install_ctx(author, &path, params, included);

        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK, "result_merge alone should install");

        // Round-trip: stored continuation should carry result_merge=true.
        let stored_hash = h.location_index.get(&path).expect("path bound");
        let stored = h.content_store.get(&stored_hash).expect("entity stored");
        let val: ciborium::Value =
            ciborium::from_reader(stored.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let rm = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("result_merge"))
            .map(|(_, v)| matches!(v, ciborium::Value::Bool(true)))
            .unwrap_or(false);
        assert!(rm, "stored continuation should preserve result_merge=true");
    }

    #[tokio::test]
    async fn test_v116_install_mutex_result_merge_and_result_field() {
        // v1.16 §3.2: result_merge + result_field MUST reject with
        // 400 invalid_continuation.
        let h = make_handler();
        let author = Hash::compute("test", b"author-rm-2");
        let cap = make_cap_entity_for_install(author, author, None);
        let cap_hash = cap.content_hash;
        let included: HashMap<Hash, Entity> = [(cap_hash, cap.clone())].into();

        let static_params = ciborium::Value::Map(vec![(
            ciborium::Value::Text("x".into()),
            ciborium::Value::Text("y".into()),
        )]);

        let path = format!("/{}/system/continuation/suspended/rm-2", test_peer_id());
        let params = make_install_params_v116(
            "app/handler",
            "process",
            cap_hash,
            Some(static_params),
            Some("dyn"),
            true,
        );
        let ctx = make_install_ctx(author, &path, params, included);

        let result = h.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);

        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let code = val
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .unwrap()
            .1
            .as_text()
            .unwrap()
            .to_string();
        assert_eq!(code, "invalid_continuation");
    }

    #[test]
    fn test_v116_assemble_params_merge_shallow_union() {
        // v1.16 §3.6 Step 2: result keys win on collision.
        let static_params = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("scaffold"), entity_ecf::text("S")),
            (entity_ecf::text("collide"), entity_ecf::text("static")),
        ]));
        let result = cbor(ciborium::Value::Map(vec![
            (ciborium::Value::Text("collide".into()), ciborium::Value::Text("dynamic".into())),
            (ciborium::Value::Text("added".into()), ciborium::Value::Text("from_result".into())),
        ]));
        let (assembled, degraded) =
            assemble_params_merge(&Some(static_params), &result).unwrap();
        assert!(!degraded);
        let v = decode(&assembled);
        let map = v.as_map().unwrap();
        // 3 keys: scaffold + collide + added (collide overwritten, not duplicated).
        assert_eq!(map.len(), 3, "merged map must dedup overlapping keys");
        let get = |k: &str| -> Option<&ciborium::Value> {
            map.iter().find(|(mk, _)| mk.as_text() == Some(k)).map(|(_, mv)| mv)
        };
        assert_eq!(get("scaffold").and_then(|x| x.as_text()), Some("S"));
        assert_eq!(get("collide").and_then(|x| x.as_text()), Some("dynamic"));
        assert_eq!(get("added").and_then(|x| x.as_text()), Some("from_result"));
    }

    #[test]
    fn test_v116_assemble_params_merge_non_map_value_degrades() {
        // v1.16 §3.4: non-map post-transform value degrades to static-only
        // params and signals the merge_value_not_map marker.
        let static_params = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("scaffold"), entity_ecf::text("S")),
        ]));
        let result = cbor(ciborium::Value::Text("not-a-map".into()));
        let (assembled, degraded) =
            assemble_params_merge(&Some(static_params), &result).unwrap();
        assert!(degraded, "non-map value MUST flag degradation");
        let v = decode(&assembled);
        let map = v.as_map().unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(
            map[0].0.as_text(),
            Some("scaffold"),
            "static-only params on degrade"
        );
    }

    #[test]
    fn test_v116_assemble_params_merge_absent_static_params() {
        // v1.16 §3.6 Step 2: absent static params + merge mode → result map is
        // the assembled params verbatim.
        let result = cbor(ciborium::Value::Map(vec![(
            ciborium::Value::Text("only".into()),
            ciborium::Value::Text("from-result".into()),
        )]));
        let (assembled, degraded) = assemble_params_merge(&None, &result).unwrap();
        assert!(!degraded);
        let v = decode(&assembled);
        let map = v.as_map().unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].0.as_text(), Some("only"));
        assert_eq!(map[0].1.as_text(), Some("from-result"));
    }

    // -----------------------------------------------------------------
    // v1.20 §3.10.1 + §3.10.6 — chain-error marker path scheme + timestamp
    // -----------------------------------------------------------------

    fn marker_chainerr() -> ChainErr {
        ChainErr {
            chain_id: "chain-xyz".to_string(),
            request_id: "req-1".to_string(),
            step_index: "req-1".to_string(),
        }
    }

    /// v1.20 §3.10.1 — the bound marker lands at a path whose terminal
    /// segment is the marker's own content_hash in V7 §3.5 hex form.
    /// Reading the location_index at that exact path returns the marker.
    #[tokio::test]
    async fn test_marker_path_includes_v1_20_terminal_hash() {
        let h = make_handler();
        let ce = marker_chainerr();
        let ts = capture_failure_timestamp_ms();
        h.write_lost_error_marker(
            &ce,
            "entity://peerB/system/tree",
            403,
            CODE_CAPABILITY_DENIED,
            ts,
            None,
        );
        // Find a marker under the v1.20 path prefix.
        let prefix = format!(
            "/{}/system/runtime/chain-errors/lost/chain-xyz/req-1/capability_denied/",
            test_peer_id(),
        );
        let entries = h.location_index.list(&prefix);
        assert_eq!(entries.len(), 1, "exactly one marker bound");
        let entry = &entries[0];
        // Path has 5 segments after the peer_id prefix.
        let tail = entry.path.strip_prefix(&prefix).unwrap();
        assert_eq!(tail.len(), 66, "terminal hex segment is 66 chars (V7 §3.5)");
        assert!(
            tail.starts_with("00"),
            "ECFv1-SHA-256 hex has the 00 format-code prefix"
        );
        // The marker entity's content_hash matches the terminal segment.
        let marker = h.content_store.get(&entry.hash).unwrap();
        assert_eq!(marker.entity_type, "system/runtime/chain-error-lost");
        assert_eq!(marker.content_hash.to_hex(), tail);
    }

    /// v1.20 §3.10.6 — distinct timestamps captured at failure-origination
    /// yield distinct marker `content_hash` → distinct terminal segments →
    /// distinct paths. Tree IS the event log: 3 occurrences → 3 paths
    /// coexist under the same `{reason}` prefix.
    #[tokio::test]
    async fn test_distinct_timestamps_yield_distinct_paths() {
        let h = make_handler();
        let ce = marker_chainerr();
        // 3 distinct origination timestamps — emulate 3 flaps.
        let timestamps = [1_700_000_000_000u64, 1_700_000_001_000, 1_700_000_002_000];
        for ts in &timestamps {
            h.write_lost_error_marker(
                &ce,
                "entity://peerB/system/tree",
                500,
                CODE_PROTOCOL_ERROR,
                *ts,
                None,
            );
        }
        let prefix = format!(
            "/{}/system/runtime/chain-errors/lost/chain-xyz/req-1/protocol_error/",
            test_peer_id(),
        );
        let entries = h.location_index.list(&prefix);
        assert_eq!(
            entries.len(),
            3,
            "3 distinct timestamps → 3 distinct {{marker_hash}} paths (v1.20 §3.10.6)"
        );
    }

    /// v1.20 §3.10.6 — same timestamp + same body bytes → same
    /// `content_hash` → same path. Redelivery dedupes to a `tree:put` no-op.
    #[tokio::test]
    async fn test_same_timestamp_dedups() {
        let h = make_handler();
        let ce = marker_chainerr();
        let ts = 1_700_000_000_000u64;
        // Same body twice — re-binding at the same path is a content-store
        // idempotent put.
        for _ in 0..3 {
            h.write_lost_error_marker(
                &ce,
                "entity://peerB/system/tree",
                500,
                CODE_RECV_TIMEOUT,
                ts,
                None,
            );
        }
        let prefix = format!(
            "/{}/system/runtime/chain-errors/lost/chain-xyz/req-1/recv_timeout/",
            test_peer_id(),
        );
        let entries = h.location_index.list(&prefix);
        assert_eq!(
            entries.len(),
            1,
            "same body bytes → same content_hash → one path (redelivery dedup)"
        );
    }

    /// v1.19 §3.10.5 path-safety: non-safe reasons fall back to
    /// `unspecified_error` while the original code remains in the body.
    #[tokio::test]
    async fn test_path_safety_sanitization() {
        let h = make_handler();
        let ce = marker_chainerr();
        h.write_lost_error_marker(
            &ce,
            "entity://peerB/x",
            400,
            "has/slash and space",
            1u64,
            None,
        );
        let prefix = format!(
            "/{}/system/runtime/chain-errors/lost/chain-xyz/req-1/unspecified_error/",
            test_peer_id(),
        );
        let entries = h.location_index.list(&prefix);
        assert_eq!(entries.len(), 1, "non-path-safe reason routed to unspecified_error");
        // Body still carries the raw `code` field.
        let marker = h.content_store.get(&entries[0].hash).unwrap();
        let v: ciborium::Value = ciborium::from_reader(marker.data.as_slice()).unwrap();
        let map = v.as_map().unwrap();
        let code = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, val)| val.as_text())
            .unwrap();
        assert_eq!(code, "has/slash and space", "raw code preserved in body");
    }

    /// v1.20 §3.10.4 mirror-pointer: when a `rejected_marker_hash` is
    /// passed, the marker body carries the cross-peer audit reference.
    #[tokio::test]
    async fn test_mirror_pointer_in_body() {
        let h = make_handler();
        let ce = marker_chainerr();
        let receiver_marker = entity_hash::Hash::from_bytes(&[
            0x00, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde,
            0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
            0xef, 0xde, 0xad, 0xbe, 0xef,
        ])
        .unwrap();
        h.write_lost_error_marker(
            &ce,
            "entity://peerB/y",
            403,
            CODE_CAPABILITY_DENIED,
            1u64,
            Some(receiver_marker),
        );
        let prefix = format!(
            "/{}/system/runtime/chain-errors/lost/chain-xyz/req-1/capability_denied/",
            test_peer_id(),
        );
        let entries = h.location_index.list(&prefix);
        assert_eq!(entries.len(), 1);
        let marker = h.content_store.get(&entries[0].hash).unwrap();
        let v: ciborium::Value = ciborium::from_reader(marker.data.as_slice()).unwrap();
        let map = v.as_map().unwrap();
        let mirror_field = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("rejected_marker_hash"))
            .and_then(|(_, val)| match val {
                ciborium::Value::Bytes(b) => entity_hash::Hash::from_bytes(b).ok(),
                _ => None,
            })
            .expect("rejected_marker_hash field present + bytes-decodable");
        assert_eq!(
            mirror_field, receiver_marker,
            "mirror body field equals the receiver's marker hash"
        );
    }

    // -----------------------------------------------------------------
    // helpers / category classification
    // -----------------------------------------------------------------

    #[test]
    fn test_classify_transport_failure() {
        assert_eq!(classify_transport_failure("request foo timed out after 30s"), "recv_timeout");
        assert_eq!(classify_transport_failure("reader task terminated"), "connection_broken");
        assert_eq!(classify_transport_failure("decode failed"), "protocol_error");
        // Unknown shape falls back to protocol_error per V7 §6.12.
        assert_eq!(classify_transport_failure("something else"), "protocol_error");
    }

    #[test]
    fn test_sanitize_reason_segment() {
        assert_eq!(sanitize_reason_segment("capability_denied"), "capability_denied");
        assert_eq!(sanitize_reason_segment("not_found"), "not_found");
        assert_eq!(sanitize_reason_segment("has/slash"), "unspecified_error");
        assert_eq!(sanitize_reason_segment("has space"), "unspecified_error");
        assert_eq!(sanitize_reason_segment(""), "unspecified_error");
        assert_eq!(sanitize_reason_segment("has\0null"), "unspecified_error");
    }

    #[test]
    fn test_peer_id_from_uri() {
        assert_eq!(
            peer_id_from_uri("entity://abcd/system/tree").as_deref(),
            Some("abcd")
        );
        assert_eq!(
            peer_id_from_uri("/abcd/system/tree").as_deref(),
            Some("abcd")
        );
        assert_eq!(peer_id_from_uri("system/tree"), None);
    }
}
