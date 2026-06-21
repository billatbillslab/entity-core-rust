//! system/subscription handler — subscribe + unsubscribe operations.
//!
//! The handler manages subscription lifecycle. The engine (engine.rs)
//! processes events and delivers notifications asynchronously.

pub mod engine;
pub(crate) mod chain_error;

use std::sync::Arc;

use async_trait::async_trait;
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult,
    STATUS_BAD_REQUEST, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OK, STATUS_REDIRECT,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::engine::{Engine, SubscriptionData, SubscriptionLimits};

/// The subscription handler: system/subscription with subscribe + unsubscribe.
pub struct SubscriptionHandler {
    engine: Arc<Engine>,
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
    /// Local L0 bootstrap identity entity's content hash — used by the
    /// GUIDE-CAPABILITIES §10 operator-class check (v1.2.1 Ruling 1) to
    /// gate subscriptions against sensitive prefix families
    /// (`system/capability/**`, `system/runtime/**`, `system/continuation/**`).
    identity_hash: Hash,
}

impl SubscriptionHandler {
    pub fn new(
        engine: Arc<Engine>,
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        identity_hash: Hash,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/subscription", local_peer_id);
        Self {
            engine,
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
            identity_hash,
        }
    }
}

/// Whether `pattern` falls under one of the sensitive prefix families that
/// GUIDE-CAPABILITIES §10 / GUIDE-INSPECTABILITY §3.4.1 v1.2.1 gate behind
/// operator-class authority.
///
/// Matches both peer-qualified (`/peer-id/system/capability/...`) and bare
/// (`system/capability/...`) forms by walking the segment list and looking
/// for `system/<family>` as a contiguous segment pair.
fn pattern_is_sensitive(pattern: &str) -> bool {
    let sensitive_families = ["capability", "runtime", "continuation"];
    let segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    // Bare-prefix shortcut.
    if let Some(first) = segments.first() {
        if *first == "system" {
            if let Some(second) = segments.get(1) {
                if sensitive_families.contains(second) {
                    return true;
                }
            }
        }
    }
    // Qualified-prefix shortcut: any "system/<family>" segment pair anywhere
    // after the leading peer-id-or-label segment.
    if segments.len() >= 3 && segments[1] == "system" {
        if let Some(third) = segments.get(2) {
            if sensitive_families.contains(third) {
                return true;
            }
        }
    }
    false
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for SubscriptionHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "subscribe" => self.handle_subscribe(ctx).await,
            "unsubscribe" => self.handle_unsubscribe(ctx).await,
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
        "subscriptions"
    }

    fn operations(&self) -> &[&str] {
        &["subscribe", "unsubscribe"]
    }
}

// ---------------------------------------------------------------------------
// Subscribe
// ---------------------------------------------------------------------------

impl SubscriptionHandler {
    async fn handle_subscribe(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        tracing::debug!(request_id = %ctx.request_id, "subscription: subscribe");
        let sub_req = decode_subscribe_request(&ctx.params.data)?;

        // Validate deliver_token is present
        if sub_req.deliver_token == Hash::zero() {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "missing_deliver_token",
                "deliver_token is required",
            ));
        }

        // Look up deliver_token in included entities
        let token_entity = match ctx.included.get(&sub_req.deliver_token) {
            Some(e) => e.clone(),
            None => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "missing_deliver_token",
                    "deliver_token entity not in included",
                ));
            }
        };

        // Default deliver_operation to "receive" per spec §3.1
        let deliver_op = if sub_req.deliver_operation.is_empty() {
            "receive"
        } else {
            &sub_req.deliver_operation
        };

        // Validate the token grants access to the delivery URI
        match entity_capability::CapabilityToken::from_entity(&token_entity) {
            Ok(cap) => {
                if !validate_delivery_token_scope(&cap, &sub_req.deliver_uri, deliver_op) {
                    return Ok(error_result(
                        STATUS_FORBIDDEN,
                        "deliver_token_insufficient",
                        "delivery token does not grant access to delivery URI",
                    ));
                }
            }
            Err(e) => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_deliver_token",
                    &format!("could not decode delivery token: {}", e),
                ));
            }
        }

        // SB1 (PROPOSAL-COHERENT-CAPABILITY-AUTHORITY): R1 chain-root check
        // via the unified primitive (V7 §5.5 check_creator_authority,
        // PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE).
        //
        // The deliver_token's authority chain must terminate at (or include) the
        // EXECUTE author's identity. Without this, a subscriber could reference
        // any deliver_token reachable in the content store and force deliveries
        // to that token's grantee — the "Finding 4" spam exploit.
        //
        // GR1 framing (EXTENSION-SUBSCRIPTION §3.1 GR1): this check is the
        // generalized rule for any handler that *stores or forwards* an accepted
        // deliver_token for later async delivery. Subscription is the canonical
        // store-then-deliver-later case. Future store-and-forward handlers must
        // run the same check at their input boundary.
        //
        // The chain returned by check_creator_authority is persisted below
        // alongside ctx.included entities (coherent-cap §2 chain-entity
        // persistence), so the subscription engine can resolve the deliver_token
        // chain when notification dispatch fires.
        let mut auth_chain: Vec<Entity> = Vec::new();
        // Production: `Some(...)` on both wire dispatch (verified envelope) and
        // local dispatch (peer identity, kernel passes shared.identity_hash).
        // `None` is reserved for direct-context tests / bootstrap fixtures that
        // bypass dispatch — those code paths are out of SB1's scope.
        if let Some(author) = ctx.author {
            let resolve = |h: &Hash| -> Option<Entity> {
                ctx.included
                    .get(h)
                    .cloned()
                    .or_else(|| self.content_store.get(h))
            };
            let auth_result = match entity_protocol::check_creator_authority(
                &sub_req.deliver_token,
                &author,
                &ctx.included,
                resolve,
            ) {
                Ok(r) => r,
                Err(_) => {
                    return Ok(error_result(
                        STATUS_NOT_FOUND,
                        "chain_unreachable",
                        "deliver_token authority chain has unreachable links",
                    ));
                }
            };
            if !auth_result.found {
                return Ok(error_result(
                    STATUS_FORBIDDEN,
                    "embedded_cap_unauthorized",
                    "subscriber identity not in deliver_token authority chain",
                ));
            }
            auth_chain = auth_result.chain;
        }

        // Default events if empty
        let events = if sub_req.events.is_empty() {
            vec!["created".into(), "updated".into(), "deleted".into()]
        } else {
            sub_req.events.clone()
        };

        // Extract pattern from resource target
        let pattern = match ctx.resource_target.as_ref().and_then(|r| r.targets.first()) {
            Some(p) if !p.is_empty() => p.clone(),
            _ => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "resource target pattern required",
                ));
            }
        };

        // GUIDE-CAPABILITIES §10 (v1.2.1 Ruling 1) — operator-class gate for
        // sensitive prefix families. system/capability/**, system/runtime/**,
        // and system/continuation/** subscriptions require the caller's
        // capability chain to (a) root at the local peer's L0 bootstrap
        // identity AND (b) every link to explicitly enumerate the target
        // pattern (no wildcards). Defense-in-depth: the subscription engine
        // would otherwise let a wide cap-bearer (`*` scope) harvest signature
        // material, identity tokens, or chain-error markers from these
        // path families — the L3-app-attack named in
        // reviews/SECURITY-AUDIT-INSPECTABILITY-BASELINE §5.1.
        if pattern_is_sensitive(&pattern) {
            let cap_hash = match ctx.capability_hash {
                Some(h) => h,
                None => {
                    return Ok(error_result(
                        STATUS_FORBIDDEN,
                        "sensitive_path",
                        "subscriptions to system/capability/, system/runtime/, \
                         or system/continuation/ require operator-class authority",
                    ));
                }
            };
            let content_store_for_resolve = self.content_store.clone();
            let operator_class = entity_protocol::is_operator_class_for(
                &cap_hash,
                &pattern,
                &self.identity_hash,
                |h| content_store_for_resolve.get(h),
            );
            if !operator_class {
                tracing::warn!(
                    request_id = %ctx.request_id,
                    pattern = %pattern,
                    "subscription refused — sensitive prefix requires operator-class authority"
                );
                return Ok(error_result(
                    STATUS_FORBIDDEN,
                    "sensitive_path",
                    "subscriptions to system/capability/, system/runtime/, \
                     or system/continuation/ require operator-class authority",
                ));
            }
        }

        // EXTENSION-SUBSCRIPTION §2.3 v3.13: include_payload read authorization.
        // Subscribing is a distinct capability from reading. If the caller asks
        // the server to bundle entity content into deliveries, the server MUST
        // verify the caller's cap covers tree:get on the resource — same authz
        // surface as a direct tree:get, just enforced server-side before push.
        // 403 payload_unauthorized when missing. Caller with subscribe-but-not-
        // get still receives lean hashes-only deliveries by omitting the flag.
        if sub_req.include_payload {
            let cap_ok = match ctx.caller_capability.as_ref() {
                Some(cap) => {
                    let resource_rt = entity_capability::ResourceTarget {
                        targets: vec![pattern.clone()],
                        exclude: vec![],
                    };
                    entity_capability::check_permission(
                        "get",
                        "system/tree",
                        &self.local_peer_id,
                        Some(&resource_rt),
                        cap,
                        &self.local_peer_id,
                    )
                }
                None => false,
            };
            if !cap_ok {
                return Ok(error_result(
                    STATUS_FORBIDDEN,
                    "payload_unauthorized",
                    "include_payload requires tree:get on the subscribed resource",
                ));
            }
        }

        let author = ctx.author.unwrap_or(Hash::zero());

        // Check for renewal: engine match OR orphaned tree entity
        let existing_id = self
            .engine
            .find_renewal(author, &pattern, &sub_req.deliver_uri)
            .or_else(|| {
                // Fallback: scan tree for orphaned subscription entities
                // (engine may have terminated the subscription during delivery)
                self.find_tree_duplicate(&pattern, &sub_req.deliver_uri)
            });

        // S1: Capacity check — only for new subscriptions (renewals don't increase count)
        if existing_id.is_none() {
            if let Some(redirect) = self.check_capacity(&pattern)? {
                return Ok(redirect);
            }
        }

        if let Some(existing_id) = existing_id {
            return self.handle_renewal(
                &existing_id,
                &pattern,
                author,
                &sub_req,
                &events,
                &token_entity,
                &ctx.included,
            );
        }

        // Generate subscription ID
        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let subscription_id = format!("sub-{}", now_ms);

        // Build subscription data
        let sub_data = SubscriptionData {
            subscription_id: subscription_id.clone(),
            pattern: pattern.clone(),
            events: events.clone(),
            deliver_uri: sub_req.deliver_uri.clone(),
            deliver_operation: sub_req.deliver_operation.clone(),
            subscriber_identity: author,
            deliver_token: token_entity.content_hash,
            created_at: now_ms / 1_000_000, // convert to millis
            limits: sub_req.limits.clone(),
            include_payload: sub_req.include_payload,
        };

        // Store subscription entity
        let sub_entity = encode_subscription_entity(&sub_data)?;
        let hash = self
            .content_store
            .put(sub_entity)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let sub_path = format!("/{}/system/subscription/{}", self.local_peer_id, subscription_id);
        self.location_index.set(&sub_path, hash);

        // Store delivery token entity
        self.content_store
            .put(token_entity)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // Persist the deliver_token's authority chain (coherent-cap §2 chain-
        // entity persistence — the chain is the value `check_creator_authority`
        // returned, no re-walk). Idempotent puts; safe to combine with the
        // broader included-map persistence below.
        for cap_entity in auth_chain {
            let _ = self.content_store.put(cap_entity);
        }

        // Store all included entities (granter identities, signatures, etc.).
        // These are needed alongside the cap chain for the subscription engine
        // to verify and re-issue notifications.
        for entity in ctx.included.values() {
            let _ = self.content_store.put(entity.clone());
        }

        // Register in engine
        self.engine.register(sub_data);

        tracing::debug!(
            subscription_id = %subscription_id,
            pattern = %pattern,
            deliver_uri = %sub_req.deliver_uri,
            events = ?events,
            "subscription: created"
        );

        // Build response
        let mut result_fields = vec![
            (
                entity_ecf::text("events"),
                entity_ecf::Value::Array(events.iter().map(entity_ecf::text).collect()),
            ),
            (
                entity_ecf::text("pattern"),
                entity_ecf::text(&pattern),
            ),
            (
                entity_ecf::text("subscription_id"),
                entity_ecf::text(&subscription_id),
            ),
        ];
        if let Some(ref limits) = sub_req.limits {
            let mut limit_fields = Vec::new();
            if let Some(max) = limits.max_events {
                limit_fields.push((
                    entity_ecf::text("max_events"),
                    entity_ecf::integer(max as i64),
                ));
            }
            if let Some(max) = limits.max_duration_ms {
                limit_fields.push((
                    entity_ecf::text("max_duration_ms"),
                    entity_ecf::integer(max as i64),
                ));
            }
            if let Some(rate) = limits.rate_limit {
                limit_fields.push((
                    entity_ecf::text("rate_limit"),
                    entity_ecf::integer(rate as i64),
                ));
            }
            result_fields.push((
                entity_ecf::text("limits"),
                entity_ecf::Value::Map(limit_fields),
            ));
        }
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(result_fields));
        let result = Entity::new("system/subscription/result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }

    /// Check subscriber capacity for the given prefix pattern.
    ///
    /// Reads `max_subscribers_per_prefix` from `/{peer_id}/system/config/subscription`.
    /// If the limit is set and the current count of subscriptions for the prefix
    /// meets or exceeds it, returns a 303 redirect response.
    fn check_capacity(&self, pattern: &str) -> Result<Option<HandlerResult>, HandlerError> {
        let config_path = format!("/{}/system/config/subscription", self.local_peer_id);
        let max_subscribers = match self.location_index.get(&config_path) {
            Some(hash) => match self.content_store.get(&hash) {
                Some(entity) => decode_max_subscribers_per_prefix(&entity.data),
                None => None,
            },
            None => None,
        };

        let max = match max_subscribers {
            Some(max) => max,
            None => return Ok(None), // No limit configured
        };

        // Count existing subscriptions matching this prefix
        let count = self.count_subscriptions_for_prefix(pattern);

        if count >= max {
            tracing::debug!(
                pattern = %pattern,
                count = count,
                max = max,
                "subscription capacity reached, returning redirect"
            );
            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("capacity"),
                    entity_ecf::integer(max as i64),
                ),
                (
                    entity_ecf::text("prefix"),
                    entity_ecf::text(pattern),
                ),
                (
                    entity_ecf::text("reason"),
                    entity_ecf::text("max_subscribers_per_prefix reached"),
                ),
            ]));
            let result = Entity::new("system/subscription/redirect", data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            return Ok(Some(HandlerResult {
                status: STATUS_REDIRECT,
                result,
                included: std::collections::HashMap::new(),
            }));
        }

        Ok(None)
    }

    /// Count the number of active subscriptions for a given prefix pattern.
    ///
    /// Iterates stored subscription entities under the subscription tree prefix
    /// and counts those whose pattern matches the requested prefix.
    fn count_subscriptions_for_prefix(&self, pattern: &str) -> u64 {
        let prefix = format!("/{}/system/subscription/", self.local_peer_id);
        let entries = self.location_index.list(&prefix);
        let mut count = 0u64;
        for entry in &entries {
            if let Some(entity) = self.content_store.get(&entry.hash) {
                if entity.entity_type == "system/subscription" {
                    if let Some(sub_pattern) = extract_pattern_from_sub_entity(&entity) {
                        if sub_pattern == pattern {
                            count += 1;
                        }
                    }
                }
            }
        }
        count
    }

    /// Scan tree for an orphaned subscription entity matching (pattern, deliver_uri).
    /// This catches cases where the engine terminated a subscription (e.g., during
    /// delivery) but the tree entity was not cleaned up.
    fn find_tree_duplicate(&self, pattern: &str, deliver_uri: &str) -> Option<String> {
        let prefix = format!("/{}/system/subscription/", self.local_peer_id);
        let entries = self.location_index.list(&prefix);
        for entry in &entries {
            if let Some(entity) = self.content_store.get(&entry.hash) {
                if entity.entity_type == "system/subscription" {
                    let ep = extract_pattern_from_sub_entity(&entity);
                    let edu = extract_deliver_uri_from_entity(&entity);
                    if ep.as_deref() == Some(pattern) && edu.as_deref() == Some(deliver_uri) {
                        // Extract subscription ID from path
                        let id = entry.path.strip_prefix(&prefix)?;
                        return Some(id.to_string());
                    }
                }
            }
        }
        None
    }

    fn handle_renewal(
        &self,
        existing_id: &str,
        pattern: &str,
        author: Hash,
        sub_req: &SubscribeRequest,
        events: &[String],
        token_entity: &Entity,
        included: &std::collections::HashMap<Hash, Entity>,
    ) -> Result<HandlerResult, HandlerError> {
        // Remove from engine (may already be absent if terminated)
        self.engine.remove(existing_id);

        // Remove old entity from tree
        let sub_path = format!("/{}/system/subscription/{}", self.local_peer_id, existing_id);
        self.location_index.remove(&sub_path);

        // Build updated subscription data (use caller's pattern/author directly)
        let sub_data = SubscriptionData {
            subscription_id: existing_id.to_string(),
            pattern: pattern.to_string(),
            events: events.to_vec(),
            deliver_uri: sub_req.deliver_uri.clone(),
            deliver_operation: sub_req.deliver_operation.clone(),
            subscriber_identity: author,
            deliver_token: token_entity.content_hash,
            created_at: web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            limits: sub_req.limits.clone(),
            include_payload: sub_req.include_payload,
        };

        // Store updated entity
        let sub_entity = encode_subscription_entity(&sub_data)?;
        let hash = self
            .content_store
            .put(sub_entity)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        self.location_index.set(&sub_path, hash);

        // Store new token + all included entities (delegation chain)
        self.content_store
            .put(token_entity.clone())
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        for entity in included.values() {
            let _ = self.content_store.put(entity.clone());
        }

        // Re-register in engine
        self.engine.register(sub_data);

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("events"),
                entity_ecf::Value::Array(events.iter().map(entity_ecf::text).collect()),
            ),
            (
                entity_ecf::text("pattern"),
                entity_ecf::text(pattern),
            ),
            (entity_ecf::text("renewed"), entity_ecf::bool_val(true)),
            (
                entity_ecf::text("subscription_id"),
                entity_ecf::text(existing_id),
            ),
        ]));
        let result = Entity::new("system/subscription/result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Unsubscribe
// ---------------------------------------------------------------------------

impl SubscriptionHandler {
    async fn handle_unsubscribe(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let subscription_id = decode_unsubscribe_request(&ctx.params.data)?;
        tracing::debug!(
            request_id = %ctx.request_id,
            subscription_id = %subscription_id,
            "subscription: unsubscribe"
        );

        // Look up subscription
        let sub_path = format!("/{}/system/subscription/{}", self.local_peer_id, subscription_id);
        let hash = match self.location_index.get(&sub_path) {
            Some(h) => h,
            None => {
                return Ok(error_result(
                    STATUS_NOT_FOUND,
                    "subscription_not_found",
                    &format!("subscription {} not found", subscription_id),
                ));
            }
        };

        // Verify ownership
        if let Some(entity) = self.content_store.get(&hash) {
            if let Some(owner) = extract_subscriber_from_entity(&entity) {
                if let Some(author) = ctx.author {
                    if owner != author {
                        return Ok(error_result(
                            STATUS_FORBIDDEN,
                            "not_subscription_owner",
                            "only the subscription owner can unsubscribe",
                        ));
                    }
                }
            }
        }

        // Remove from location index and engine
        self.location_index.remove(&sub_path);
        self.engine.remove(&subscription_id);

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("removed"),
            entity_ecf::bool_val(true),
        )]));
        let result = Entity::new("system/subscription/cancel-result", data)
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

struct SubscribeRequest {
    events: Vec<String>,
    deliver_uri: String,
    deliver_operation: String,
    deliver_token: Hash,
    limits: Option<SubscriptionLimits>,
    /// PROPOSAL-CONVERGENT-MIRRORING §2: opt-in subscriber flag asking the
    /// server to bundle the changed entity into the delivery envelope's
    /// `included` map. Default false.
    include_payload: bool,
}

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

fn decode_subscribe_request(params_data: &[u8]) -> Result<SubscribeRequest, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(params_data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode params: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut events = Vec::new();
    let mut deliver_uri = String::new();
    let mut deliver_operation = String::new();
    let mut deliver_token = Hash::zero();
    let mut limits = None;
    let mut include_payload = false;

    for (pk, pv) in map {
        match pk.as_text() {
            Some("include_payload") => {
                if let ciborium::Value::Bool(b) = pv {
                    include_payload = *b;
                }
            }
            Some("events") => {
                if let Some(arr) = pv.as_array() {
                    events = arr
                        .iter()
                        .filter_map(|e| e.as_text().map(|s| s.to_string()))
                        .collect();
                }
            }
            Some("deliver_to") => {
                if let Some(dt_map) = pv.as_map() {
                    for (dk, dv) in dt_map {
                        match dk.as_text() {
                            Some("uri") => {
                                deliver_uri = dv.as_text().unwrap_or("").to_string();
                            }
                            Some("operation") => {
                                deliver_operation = dv.as_text().unwrap_or("").to_string();
                            }
                            _ => {}
                        }
                    }
                }
            }
            Some("deliver_token") => {
                if let ciborium::Value::Bytes(b) = pv {
                    deliver_token = Hash::from_bytes(b).unwrap_or(Hash::zero());
                }
            }
            Some("limits") => {
                limits = decode_limits(pv);
            }
            _ => {}
        }
    }

    Ok(SubscribeRequest {
        events,
        deliver_uri,
        deliver_operation,
        deliver_token,
        limits,
        include_payload,
    })
}

fn decode_unsubscribe_request(params_data: &[u8]) -> Result<String, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(params_data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode params: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    for (pk, pv) in map {
        if pk.as_text() == Some("subscription_id") {
            return pv
                .as_text()
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    HandlerError::InvalidParams("subscription_id not a string".into())
                });
        }
    }
    Err(HandlerError::InvalidParams(
        "missing subscription_id".into(),
    ))
}

/// Decode `max_subscribers_per_prefix` from a `system/config/subscription` entity's data.
fn decode_max_subscribers_per_prefix(data: &[u8]) -> Option<u64> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("max_subscribers_per_prefix") {
            return v.as_integer().map(|i| i128::from(i) as u64);
        }
    }
    None
}

fn decode_limits(v: &ciborium::Value) -> Option<SubscriptionLimits> {
    let map = v.as_map()?;
    let mut max_events = None;
    let mut max_duration_ms = None;
    let mut rate_limit = None;

    for (k, v) in map {
        match k.as_text() {
            Some("max_events") => max_events = v.as_integer().map(|i| i128::from(i) as u64),
            Some("max_duration_ms") => {
                max_duration_ms = v.as_integer().map(|i| i128::from(i) as u64)
            }
            Some("rate_limit") => rate_limit = v.as_integer().map(|i| i128::from(i) as u64),
            _ => {}
        }
    }
    Some(SubscriptionLimits {
        max_events,
        max_duration_ms,
        rate_limit,
    })
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Check if any include pattern covers the value.
/// Matches Go's scopeIncludes: wildcard, exact, and subtree (base + children).
fn scope_includes(include: &[String], value: &str) -> bool {
    for pattern in include {
        if pattern == "*" || pattern == value {
            return true;
        }
        // Subtree: "system/inbox/*" matches "system/inbox" and "system/inbox/anything"
        if pattern.ends_with('*') && pattern.len() > 1 {
            let prefix = &pattern[..pattern.len() - 1]; // e.g. "system/inbox/"
            let base = prefix.strip_suffix('/').unwrap_or(prefix);
            if value == base || value.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

fn validate_delivery_token_scope(
    cap: &entity_capability::CapabilityToken,
    deliver_uri: &str,
    deliver_operation: &str,
) -> bool {
    // Token must grant access to system/inbox handler + the delivery URI + the operation
    for grant in &cap.grants {
        if !scope_includes(&grant.handlers.include, "system/inbox") {
            continue;
        }
        if !scope_includes(&grant.resources.include, deliver_uri) {
            continue;
        }
        if !scope_includes(&grant.operations.include, deliver_operation) {
            continue;
        }
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Encode helpers
// ---------------------------------------------------------------------------

/// Encode a `SubscriptionData` as a `system/subscription` entity.
/// Inverse of `decode_subscription_entity`. Exposed publicly so tests
/// and fixtures can plant subscription entities directly without going
/// through the full `subscribe` op ceremony.
pub fn encode_subscription_entity(sub: &SubscriptionData) -> Result<Entity, HandlerError> {
    let mut fields = vec![
        (
            entity_ecf::text("created_at"),
            entity_ecf::integer(sub.created_at as i64),
        ),
        (
            entity_ecf::text("deliver_operation"),
            entity_ecf::text(&sub.deliver_operation),
        ),
        (
            entity_ecf::text("deliver_token"),
            entity_ecf::Value::Bytes(sub.deliver_token.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("deliver_uri"),
            entity_ecf::text(&sub.deliver_uri),
        ),
        (
            entity_ecf::text("events"),
            entity_ecf::Value::Array(sub.events.iter().map(entity_ecf::text).collect()),
        ),
        (
            entity_ecf::text("pattern"),
            entity_ecf::text(&sub.pattern),
        ),
        (
            entity_ecf::text("subscriber_identity"),
            entity_ecf::Value::Bytes(sub.subscriber_identity.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("subscription_id"),
            entity_ecf::text(&sub.subscription_id),
        ),
    ];

    if let Some(ref limits) = sub.limits {
        let mut limit_fields = Vec::new();
        if let Some(max) = limits.max_events {
            limit_fields.push((
                entity_ecf::text("max_events"),
                entity_ecf::integer(max as i64),
            ));
        }
        if let Some(max) = limits.max_duration_ms {
            limit_fields.push((
                entity_ecf::text("max_duration_ms"),
                entity_ecf::integer(max as i64),
            ));
        }
        if let Some(rate) = limits.rate_limit {
            limit_fields.push((
                entity_ecf::text("rate_limit"),
                entity_ecf::integer(rate as i64),
            ));
        }
        fields.push((
            entity_ecf::text("limits"),
            entity_ecf::Value::Map(limit_fields),
        ));
    }

    // include_payload: emit only when true (default false is absent — matches
    // the "optional field SHOULD be absent" convention from V7).
    if sub.include_payload {
        fields.push((
            entity_ecf::text("include_payload"),
            entity_ecf::bool_val(true),
        ));
    }

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    Entity::new("system/subscription", data).map_err(|e| HandlerError::Internal(e.to_string()))
}

/// Decode a `system/subscription` entity back into `SubscriptionData`.
/// Inverse of `encode_subscription_entity`. Returns `None` if the entity
/// is not a `system/subscription` or any required field is missing.
///
/// Used by `Engine::load()` to rebuild the routing index from the tree
/// after restart.
pub(crate) fn decode_subscription_entity(entity: &Entity) -> Option<SubscriptionData> {
    if entity.entity_type != "system/subscription" {
        return None;
    }
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;

    let mut subscription_id: Option<String> = None;
    let mut pattern: Option<String> = None;
    let mut events: Vec<String> = Vec::new();
    let mut deliver_uri: Option<String> = None;
    let mut deliver_operation: Option<String> = None;
    let mut subscriber_identity: Option<Hash> = None;
    let mut deliver_token: Option<Hash> = None;
    let mut created_at: Option<u64> = None;
    let mut limits: Option<SubscriptionLimits> = None;
    let mut include_payload = false;

    for (k, v) in map {
        match k.as_text() {
            Some("include_payload") => {
                if let ciborium::Value::Bool(b) = v {
                    include_payload = *b;
                }
            }
            Some("subscription_id") => {
                subscription_id = v.as_text().map(String::from);
            }
            Some("pattern") => {
                pattern = v.as_text().map(String::from);
            }
            Some("events") => {
                if let Some(arr) = v.as_array() {
                    events = arr
                        .iter()
                        .filter_map(|e| e.as_text().map(String::from))
                        .collect();
                }
            }
            Some("deliver_uri") => {
                deliver_uri = v.as_text().map(String::from);
            }
            Some("deliver_operation") => {
                deliver_operation = v.as_text().map(String::from);
            }
            Some("subscriber_identity") => {
                if let Some(b) = v.as_bytes() {
                    subscriber_identity = Hash::from_bytes(b).ok();
                }
            }
            Some("deliver_token") => {
                if let Some(b) = v.as_bytes() {
                    deliver_token = Hash::from_bytes(b).ok();
                }
            }
            Some("created_at") => {
                created_at = v.as_integer().map(|i| i128::from(i) as u64);
            }
            Some("limits") => {
                limits = decode_limits(v);
            }
            _ => {}
        }
    }

    Some(SubscriptionData {
        subscription_id: subscription_id?,
        pattern: pattern?,
        events,
        deliver_uri: deliver_uri?,
        deliver_operation: deliver_operation?,
        subscriber_identity: subscriber_identity?,
        deliver_token: deliver_token?,
        created_at: created_at?,
        limits,
        include_payload,
    })
}

fn extract_pattern_from_sub_entity(entity: &Entity) -> Option<String> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("pattern") {
            return v.as_text().map(|s| s.to_string());
        }
    }
    None
}

fn extract_deliver_uri_from_entity(entity: &Entity) -> Option<String> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("deliver_uri") {
            return v.as_text().map(|s| s.to_string());
        }
    }
    None
}

fn extract_subscriber_from_entity(entity: &Entity) -> Option<Hash> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("subscriber_identity") {
            if let ciborium::Value::Bytes(b) = v {
                return Hash::from_bytes(b).ok();
            }
        }
    }
    None
}

fn error_result(status: u32, code: &str, message: &str) -> HandlerResult {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    // Canonical error type per ENTITY-NATIVE-TYPE-SYSTEM — matches Go's
    // TypeError so cross-impl SDKs read {code,message} from the entity
    // instead of falling back to status-default codes.
    let result = Entity::new("system/protocol/error", data).unwrap();
    HandlerResult { status, result, included: std::collections::HashMap::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id() -> String {
        "test_peer".to_string()
    }

    fn make_handler() -> (SubscriptionHandler, Arc<Engine>) {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(Engine::new(store.clone(), index.clone(), test_peer_id()));
        let handler = SubscriptionHandler::new(engine.clone(), store, index, test_peer_id(), Hash::zero());
        (handler, engine)
    }

    #[test]
    fn test_pattern() {
        let (handler, _) = make_handler();
        assert_eq!(handler.pattern(), "/test_peer/system/subscription");
        assert_eq!(handler.name(), "subscriptions");
        assert_eq!(handler.operations(), &["subscribe", "unsubscribe"]);
    }

    #[tokio::test]
    async fn test_unknown_operation() {
        let (handler, _) = make_handler();
        let params = make_params("primitive/null", entity_ecf::Value::Null);
        let execute = make_execute();
        let ctx = HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            pattern: "/test_peer/system/subscription".to_string(),
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
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    fn make_params(type_name: &str, data: entity_ecf::Value) -> Entity {
        Entity::new(type_name, entity_ecf::to_ecf(&data)).unwrap()
    }

    fn make_execute() -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("request_id"), entity_ecf::text("r1")),
        ]));
        Entity::new(entity_types::TYPE_EXECUTE, data).unwrap()
    }

    #[tokio::test]
    async fn test_unsubscribe_not_found() {
        let (handler, _) = make_handler();
        let params = make_params("system/subscription/cancel-params", entity_ecf::Value::Map(vec![(
            entity_ecf::text("subscription_id"),
            entity_ecf::text("sub-nonexistent"),
        )]));
        let execute = make_execute();
        let ctx = HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            pattern: "/test_peer/system/subscription".to_string(),
            suffix: String::new(),
            resource_target: None,
            author: None,
            session_peer_id: None,
            request_id: "r1".to_string(),
            operation: "unsubscribe".to_string(),
            execute_fn: None,
            included: std::collections::HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        };
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    #[test]
    fn test_validate_delivery_token_scope() {
        use entity_capability::*;

        // Exact match on all 3 dimensions
        let cap = CapabilityToken {
            grants: vec![GrantEntry {
                handlers: PathScope::new(vec!["system/inbox".into()]),
                resources: PathScope::new(vec!["user/inbox".into()]),
                operations: IdScope::new(vec!["receive".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }],
            granter: entity_capability::Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        assert!(validate_delivery_token_scope(&cap, "user/inbox", "receive"));
        assert!(!validate_delivery_token_scope(&cap, "other/inbox", "receive"));
        // Wrong operation must fail
        assert!(!validate_delivery_token_scope(&cap, "user/inbox", "write"));

        // Wildcard grants pass all dimensions
        let wildcard_cap = CapabilityToken {
            grants: vec![GrantEntry {
                handlers: PathScope::new(vec!["*".into()]),
                resources: PathScope::new(vec!["*".into()]),
                operations: IdScope::new(vec!["*".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }],
            granter: entity_capability::Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        assert!(validate_delivery_token_scope(&wildcard_cap, "any/uri", "any_op"));

        // Subtree: "system/inbox/*" matches base "system/inbox"
        let subtree_cap = CapabilityToken {
            grants: vec![GrantEntry {
                handlers: PathScope::new(vec!["system/inbox/*".into()]),
                resources: PathScope::new(vec!["user/inbox/*".into()]),
                operations: IdScope::new(vec!["*".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }],
            granter: entity_capability::Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        assert!(validate_delivery_token_scope(&subtree_cap, "user/inbox", "receive"));
        assert!(validate_delivery_token_scope(&subtree_cap, "user/inbox/sub", "receive"));
        assert!(!validate_delivery_token_scope(&subtree_cap, "other/path", "receive"));
    }

    #[test]
    fn test_scope_includes() {
        // Wildcard
        assert!(scope_includes(&["*".into()], "anything"));
        // Exact match
        assert!(scope_includes(&["system/inbox".into()], "system/inbox"));
        assert!(!scope_includes(&["system/inbox".into()], "system/other"));
        // Subtree: base path matches
        assert!(scope_includes(&["system/inbox/*".into()], "system/inbox"));
        // Subtree: child path matches
        assert!(scope_includes(&["system/inbox/*".into()], "system/inbox/child"));
        // Subtree: unrelated path doesn't match
        assert!(!scope_includes(&["system/inbox/*".into()], "system/other"));
        // Empty include list
        assert!(!scope_includes(&[], "anything"));
    }

    #[test]
    fn test_encode_subscription_entity() {
        let sub = SubscriptionData {
            subscription_id: "sub-1".to_string(),
            pattern: "app/*".to_string(),
            events: vec!["created".into()],
            deliver_uri: "user/inbox".to_string(),
            deliver_operation: "receive".to_string(),
            subscriber_identity: Hash::zero(),
            deliver_token: Hash::zero(),
            created_at: 12345,
            limits: None,
            include_payload: false,
        };
        let entity = encode_subscription_entity(&sub).unwrap();
        assert_eq!(entity.entity_type, "system/subscription");
    }

    #[test]
    fn test_encode_decode_subscription_with_include_payload() {
        let sub = SubscriptionData {
            subscription_id: "sub-ip".to_string(),
            pattern: "app/*".to_string(),
            events: vec!["created".into(), "updated".into()],
            deliver_uri: "user/inbox".to_string(),
            deliver_operation: "receive".to_string(),
            subscriber_identity: Hash::zero(),
            deliver_token: Hash::zero(),
            created_at: 12345,
            limits: None,
            include_payload: true,
        };
        let entity = encode_subscription_entity(&sub).unwrap();
        let decoded = decode_subscription_entity(&entity).expect("decode");
        assert!(decoded.include_payload, "include_payload should round-trip");
    }

    #[test]
    fn test_encode_decode_subscription_default_no_include_payload() {
        let sub = SubscriptionData {
            subscription_id: "sub-noip".to_string(),
            pattern: "app/*".to_string(),
            events: vec!["created".into()],
            deliver_uri: "user/inbox".to_string(),
            deliver_operation: "receive".to_string(),
            subscriber_identity: Hash::zero(),
            deliver_token: Hash::zero(),
            created_at: 12345,
            limits: None,
            include_payload: false,
        };
        let entity = encode_subscription_entity(&sub).unwrap();
        // include_payload absent (default false): the field key MUST NOT appear
        // in the encoded ECF bytes — V7 optional-field convention.
        let s = String::from_utf8_lossy(&entity.data);
        assert!(!s.contains("include_payload"), "include_payload should not be emitted when false");
        let decoded = decode_subscription_entity(&entity).expect("decode");
        assert!(!decoded.include_payload);
    }

    #[test]
    fn test_decode_subscribe_with_limits() {
        // Build params exactly as Go would: {deliver_to, deliver_token, events, limits}
        let token_hash = Hash::compute("test", b"token");
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("deliver_to"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("operation"), entity_ecf::text("receive")),
                    (entity_ecf::text("uri"), entity_ecf::text("system/inbox/test")),
                ]),
            ),
            (
                entity_ecf::text("deliver_token"),
                entity_ecf::Value::Bytes(token_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("events"),
                entity_ecf::Value::Array(vec![
                    entity_ecf::text("created"),
                    entity_ecf::text("updated"),
                ]),
            ),
            (
                entity_ecf::text("limits"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("max_events"),
                    entity_ecf::integer(2),
                )]),
            ),
        ]));

        let req = decode_subscribe_request(&params_data).unwrap();
        assert_eq!(req.deliver_uri, "system/inbox/test");
        assert_eq!(req.deliver_operation, "receive");
        assert_eq!(req.deliver_token, token_hash);
        assert_eq!(req.events, vec!["created", "updated"]);
        assert!(req.limits.is_some(), "limits should be decoded");
        let limits = req.limits.unwrap();
        assert_eq!(limits.max_events, Some(2), "max_events should be 2");
        assert_eq!(limits.max_duration_ms, None);
        assert_eq!(limits.rate_limit, None);
    }

    #[test]
    fn test_decode_subscribe_with_limits_ciborium() {
        // Test with ciborium encoding (non-ECF, Go's struct ordering)
        let token_hash = Hash::compute("test", b"token");
        let mut params_data = Vec::new();
        let cib_map = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("events".into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Text("created".into()),
                    ciborium::Value::Text("updated".into()),
                    ciborium::Value::Text("deleted".into()),
                ]),
            ),
            (
                ciborium::Value::Text("deliver_to".into()),
                ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("uri".into()),
                        ciborium::Value::Text("system/inbox/test-maxevents".into()),
                    ),
                    (
                        ciborium::Value::Text("operation".into()),
                        ciborium::Value::Text("receive".into()),
                    ),
                ]),
            ),
            (
                ciborium::Value::Text("deliver_token".into()),
                ciborium::Value::Bytes(token_hash.to_bytes().to_vec()),
            ),
            (
                ciborium::Value::Text("limits".into()),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("max_events".into()),
                    ciborium::Value::Integer(2.into()),
                )]),
            ),
        ]);
        ciborium::into_writer(&cib_map, &mut params_data).unwrap();

        let req = decode_subscribe_request(&params_data).unwrap();
        assert_eq!(req.deliver_uri, "system/inbox/test-maxevents");
        assert!(req.limits.is_some(), "limits should be decoded from ciborium");
        let limits = req.limits.unwrap();
        assert_eq!(limits.max_events, Some(2), "max_events should be 2");
    }

    #[test]
    fn test_check_capacity_no_config() {
        let (handler, _) = make_handler();
        // No config entity stored — should return None (no limit)
        let result = handler.check_capacity("app/*").unwrap();
        assert!(result.is_none(), "no config means no capacity limit");
    }

    #[test]
    fn test_check_capacity_under_limit() {
        let (handler, _) = make_handler();

        // Store config with max_subscribers_per_prefix = 2
        let config_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("max_subscribers_per_prefix"),
            entity_ecf::integer(2),
        )]));
        let config_entity =
            Entity::new(entity_types::TYPE_SUBSCRIPTION_CONFIG, config_data).unwrap();
        let hash = handler.content_store.put(config_entity).unwrap();
        let config_path = format!("/{}/system/config/subscription", test_peer_id());
        handler.location_index.set(&config_path, hash);

        // No subscriptions yet — should be under limit
        let result = handler.check_capacity("app/*").unwrap();
        assert!(result.is_none(), "should be under limit with 0 subscriptions");
    }

    #[test]
    fn test_check_capacity_at_limit() {
        let (handler, _) = make_handler();

        // Store config with max_subscribers_per_prefix = 1
        let config_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("max_subscribers_per_prefix"),
            entity_ecf::integer(1),
        )]));
        let config_entity =
            Entity::new(entity_types::TYPE_SUBSCRIPTION_CONFIG, config_data).unwrap();
        let hash = handler.content_store.put(config_entity).unwrap();
        let config_path = format!("/{}/system/config/subscription", test_peer_id());
        handler.location_index.set(&config_path, hash);

        // Store one subscription entity for the same pattern
        let sub_data = SubscriptionData {
            subscription_id: "sub-1".to_string(),
            pattern: "app/*".to_string(),
            events: vec!["created".into()],
            deliver_uri: "user/inbox".to_string(),
            deliver_operation: "receive".to_string(),
            subscriber_identity: Hash::zero(),
            deliver_token: Hash::zero(),
            created_at: 12345,
            limits: None,
            include_payload: false,
        };
        let sub_entity = encode_subscription_entity(&sub_data).unwrap();
        let sub_hash = handler.content_store.put(sub_entity).unwrap();
        let sub_path = format!("/{}/system/subscription/sub-1", test_peer_id());
        handler.location_index.set(&sub_path, sub_hash);

        // Now capacity check for "app/*" should return a redirect
        let result = handler.check_capacity("app/*").unwrap();
        assert!(result.is_some(), "should be at capacity");
        let redirect = result.unwrap();
        assert_eq!(redirect.status, STATUS_REDIRECT);
        assert_eq!(
            redirect.result.entity_type,
            "system/subscription/redirect"
        );
    }

    #[test]
    fn test_check_capacity_different_prefix() {
        let (handler, _) = make_handler();

        // Store config with max_subscribers_per_prefix = 1
        let config_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("max_subscribers_per_prefix"),
            entity_ecf::integer(1),
        )]));
        let config_entity =
            Entity::new(entity_types::TYPE_SUBSCRIPTION_CONFIG, config_data).unwrap();
        let hash = handler.content_store.put(config_entity).unwrap();
        let config_path = format!("/{}/system/config/subscription", test_peer_id());
        handler.location_index.set(&config_path, hash);

        // Store one subscription entity for "app/*"
        let sub_data = SubscriptionData {
            subscription_id: "sub-1".to_string(),
            pattern: "app/*".to_string(),
            events: vec!["created".into()],
            deliver_uri: "user/inbox".to_string(),
            deliver_operation: "receive".to_string(),
            subscriber_identity: Hash::zero(),
            deliver_token: Hash::zero(),
            created_at: 12345,
            limits: None,
            include_payload: false,
        };
        let sub_entity = encode_subscription_entity(&sub_data).unwrap();
        let sub_hash = handler.content_store.put(sub_entity).unwrap();
        let sub_path = format!("/{}/system/subscription/sub-1", test_peer_id());
        handler.location_index.set(&sub_path, sub_hash);

        // Different prefix "other/*" — should NOT be at capacity
        let result = handler.check_capacity("other/*").unwrap();
        assert!(result.is_none(), "different prefix should not be at capacity");
    }

    #[test]
    fn test_decode_max_subscribers_per_prefix() {
        // With value
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("max_subscribers_per_prefix"),
            entity_ecf::integer(10),
        )]));
        assert_eq!(decode_max_subscribers_per_prefix(&data), Some(10));

        // Without field
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![]));
        assert_eq!(decode_max_subscribers_per_prefix(&data), None);

        // Null value
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("max_subscribers_per_prefix"),
            entity_ecf::Value::Null,
        )]));
        assert_eq!(decode_max_subscribers_per_prefix(&data), None);
    }

    #[test]
    fn test_count_subscriptions_for_prefix() {
        let (handler, _) = make_handler();

        // Store two subscriptions for "app/*" and one for "other/*"
        for (id, pattern) in [("sub-1", "app/*"), ("sub-2", "app/*"), ("sub-3", "other/*")] {
            let sub_data = SubscriptionData {
                subscription_id: id.to_string(),
                pattern: pattern.to_string(),
                events: vec!["created".into()],
                deliver_uri: "user/inbox".to_string(),
                deliver_operation: "receive".to_string(),
                subscriber_identity: Hash::zero(),
                deliver_token: Hash::zero(),
                created_at: 12345,
                limits: None,
                include_payload: false,
            };
            let sub_entity = encode_subscription_entity(&sub_data).unwrap();
            let sub_hash = handler.content_store.put(sub_entity).unwrap();
            let sub_path = format!("/{}/system/subscription/{}", test_peer_id(), id);
            handler.location_index.set(&sub_path, sub_hash);
        }

        assert_eq!(handler.count_subscriptions_for_prefix("app/*"), 2);
        assert_eq!(handler.count_subscriptions_for_prefix("other/*"), 1);
        assert_eq!(handler.count_subscriptions_for_prefix("missing/*"), 0);
    }

    // -------------------------------------------------------------------
    // SB1 — R1 chain-root check on deliver_token
    // (PROPOSAL-COHERENT-CAPABILITY-AUTHORITY, EXTENSION-SUBSCRIPTION §3.1)
    // -------------------------------------------------------------------

    /// Build a wildcard delivery token with the given granter, grantee, and parent.
    /// Wildcard scope passes the existing scope check so SB1 is exercised in isolation.
    fn make_delivery_token(granter: Hash, grantee: Hash, parent: Option<Hash>) -> Entity {
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
            (
                entity_ecf::text("grants"),
                entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("handlers"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("operations"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                        )]),
                    ),
                    (
                        entity_ecf::text("resources"),
                        entity_ecf::Value::Map(vec![(
                            entity_ecf::text("include"),
                            entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                        )]),
                    ),
                ])]),
            ),
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

    fn make_subscribe_params(deliver_uri: &str, deliver_token: Hash) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("deliver_to"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("operation"), entity_ecf::text("receive")),
                    (entity_ecf::text("uri"), entity_ecf::text(deliver_uri)),
                ]),
            ),
            (
                entity_ecf::text("deliver_token"),
                entity_ecf::Value::Bytes(deliver_token.to_bytes().to_vec()),
            ),
        ]));
        Entity::new("system/subscription/params", data).unwrap()
    }

    fn make_subscribe_ctx(
        author: Hash,
        deliver_token: Hash,
        deliver_uri: &str,
        included: std::collections::HashMap<Hash, Entity>,
    ) -> HandlerContext {
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: make_execute(),
            params: make_subscribe_params(deliver_uri, deliver_token),
            pattern: "/test_peer/system/subscription".to_string(),
            suffix: String::new(),
            resource_target: Some(entity_capability::ResourceTarget {
                targets: vec!["app/*".to_string()],
                exclude: vec![],
            }),
            author: Some(author),
            session_peer_id: None,
            request_id: "r1".to_string(),
            operation: "subscribe".to_string(),
            execute_fn: None,
            included,
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        }
    }

    #[test]
    fn b2_pattern_is_sensitive_recognizes_three_families() {
        // GUIDE-CAPABILITIES §10 + GUIDE-INSPECTABILITY §3.4.1 v1.2.1
        // sensitive prefix families.
        assert!(pattern_is_sensitive("system/capability/grants/x"));
        assert!(pattern_is_sensitive("system/capability/"));
        assert!(pattern_is_sensitive("system/capability"));
        assert!(pattern_is_sensitive("system/runtime/chain-errors/x"));
        assert!(pattern_is_sensitive("system/continuation/foo"));
        assert!(pattern_is_sensitive("/peer-abc/system/capability/grants"));
        assert!(pattern_is_sensitive("/peer-abc/system/runtime/tap/x"));
        // Non-sensitive
        assert!(!pattern_is_sensitive("app/data"));
        assert!(!pattern_is_sensitive("system/tree/snapshots"));
        assert!(!pattern_is_sensitive("system/subscription/x"));
        assert!(!pattern_is_sensitive("/peer-abc/app/feed"));
    }

    #[tokio::test]
    async fn b2_refuses_sensitive_pattern_without_operator_class() {
        // GUIDE-CAPABILITIES §10 v1.2.1: subscriptions to sensitive prefix
        // families MUST refuse callers that are not operator-class for the
        // target. Here: no capability_hash on the ctx → fail closed with
        // STATUS_FORBIDDEN + code "sensitive_path".
        let (handler, _) = make_handler();
        let author = Hash::compute("test", b"author-A");
        let token = make_delivery_token(author, author, None);
        let token_hash = token.content_hash;
        let included: std::collections::HashMap<Hash, Entity> =
            [(token_hash, token.clone())].into();
        let mut ctx = make_subscribe_ctx(author, token_hash, "user/inbox", included);
        ctx.resource_target = Some(entity_capability::ResourceTarget {
            targets: vec!["system/capability/grants/*".to_string()],
            exclude: vec![],
        });

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_FORBIDDEN,
            "sensitive prefix without operator-class must return 403"
        );
        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let code = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(code, Some("sensitive_path"));
    }

    #[tokio::test]
    async fn test_sb1_self_issued_token_succeeds() {
        // Subscriber issues their own token (granter == author) → InChain → 200.
        let (handler, _) = make_handler();
        let author = Hash::compute("test", b"author-A");
        let token = make_delivery_token(author, author, None);
        let token_hash = token.content_hash;
        let included: std::collections::HashMap<Hash, Entity> =
            [(token_hash, token.clone())].into();

        let ctx = make_subscribe_ctx(author, token_hash, "user/inbox", included);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_OK,
            "self-issued token should subscribe successfully"
        );
    }

    #[tokio::test]
    async fn test_sb1_foreign_token_rejected() {
        // Adversary references a token rooted at admin (granter == admin, author == adversary)
        // → NotInChain → 403 embedded_cap_unauthorized. Closes Finding 4.
        let (handler, _) = make_handler();
        let admin = Hash::compute("test", b"admin-identity");
        let adversary = Hash::compute("test", b"adversary-identity");
        let admin_token = make_delivery_token(admin, admin, None);
        let token_hash = admin_token.content_hash;
        let included: std::collections::HashMap<Hash, Entity> =
            [(token_hash, admin_token.clone())].into();

        let ctx = make_subscribe_ctx(adversary, token_hash, "admin/inbox", included);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_FORBIDDEN);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let code = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(code, Some("embedded_cap_unauthorized"));
    }

    #[tokio::test]
    async fn test_sb1_chain_unreachable_404() {
        // Token references a parent that is not in included or store → Unreachable → 404.
        let (handler, _) = make_handler();
        let granter = Hash::compute("test", b"granter-G");
        let grantee = Hash::compute("test", b"grantee-A");
        let phantom = Hash::compute("test", b"phantom-parent");
        let token = make_delivery_token(granter, grantee, Some(phantom));
        let token_hash = token.content_hash;
        let included: std::collections::HashMap<Hash, Entity> =
            [(token_hash, token.clone())].into();
        // Author is grantee — not == granter, so the walk descends to the phantom parent.
        let ctx = make_subscribe_ctx(grantee, token_hash, "user/inbox", included);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let code = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(code, Some("chain_unreachable"));
    }

    /// Build a token whose grant scopes can be customized for the read-auth tests.
    /// Different from `make_delivery_token` (which is wildcarded) so we can express
    /// "subscribe but not get" vs "subscribe AND get" against `system/tree`.
    fn make_caller_token(
        granter: Hash,
        grantee: Hash,
        ops: &[&str],
        handlers: &[&str],
    ) -> entity_capability::CapabilityToken {
        let to_arr = |xs: &[&str]| {
            xs.iter()
                .map(|s| entity_ecf::text(*s))
                .collect::<Vec<_>>()
        };
        let token_entity = Entity::new(
            entity_types::TYPE_CAP_TOKEN,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("created_at"), entity_ecf::integer(0)),
                (
                    entity_ecf::text("grantee"),
                    entity_ecf::Value::Bytes(grantee.to_bytes().to_vec()),
                ),
                (
                    entity_ecf::text("granter"),
                    entity_ecf::Value::Bytes(granter.to_bytes().to_vec()),
                ),
                (
                    entity_ecf::text("grants"),
                    entity_ecf::Value::Array(vec![entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("handlers"),
                            entity_ecf::Value::Map(vec![(
                                entity_ecf::text("include"),
                                entity_ecf::Value::Array(to_arr(handlers)),
                            )]),
                        ),
                        (
                            entity_ecf::text("operations"),
                            entity_ecf::Value::Map(vec![(
                                entity_ecf::text("include"),
                                entity_ecf::Value::Array(to_arr(ops)),
                            )]),
                        ),
                        (
                            entity_ecf::text("resources"),
                            entity_ecf::Value::Map(vec![(
                                entity_ecf::text("include"),
                                entity_ecf::Value::Array(vec![entity_ecf::text("*")]),
                            )]),
                        ),
                    ])]),
                ),
            ])),
        )
        .unwrap();
        entity_capability::CapabilityToken::from_entity(&token_entity).unwrap()
    }

    fn make_subscribe_params_with_payload(
        deliver_uri: &str,
        deliver_token: Hash,
        include_payload: bool,
    ) -> Entity {
        let mut fields = vec![
            (
                entity_ecf::text("deliver_to"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("operation"), entity_ecf::text("receive")),
                    (entity_ecf::text("uri"), entity_ecf::text(deliver_uri)),
                ]),
            ),
            (
                entity_ecf::text("deliver_token"),
                entity_ecf::Value::Bytes(deliver_token.to_bytes().to_vec()),
            ),
        ];
        if include_payload {
            fields.push((
                entity_ecf::text("include_payload"),
                entity_ecf::bool_val(true),
            ));
        }
        Entity::new(
            "system/subscription/params",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(fields)),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_include_payload_without_get_grant_rejects_403() {
        // v3.13: subscribe-but-not-get + include_payload=true → 403 payload_unauthorized.
        let (handler, _) = make_handler();
        let author = Hash::compute("test", b"author-readauth");
        let token = make_delivery_token(author, author, None);
        let token_hash = token.content_hash;
        let included: std::collections::HashMap<Hash, Entity> =
            [(token_hash, token.clone())].into();

        // Caller has subscribe on system/subscription but NOT get on system/tree.
        let caller_cap = make_caller_token(
            author,
            author,
            &["subscribe"],
            &["system/subscription"],
        );

        let mut ctx = make_subscribe_ctx(author, token_hash, "user/inbox", included);
        ctx.caller_capability = Some(caller_cap);
        ctx.params = make_subscribe_params_with_payload("user/inbox", token_hash, true);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_FORBIDDEN);
        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let code = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(code, Some("payload_unauthorized"));
    }

    #[tokio::test]
    async fn test_include_payload_with_get_grant_succeeds() {
        // v3.13: subscribe+get + include_payload=true → 200, persists include_payload.
        let (handler, _) = make_handler();
        let author = Hash::compute("test", b"author-getok");
        let token = make_delivery_token(author, author, None);
        let token_hash = token.content_hash;
        let included: std::collections::HashMap<Hash, Entity> =
            [(token_hash, token.clone())].into();

        // Caller has both subscribe and get across handlers.
        let caller_cap = make_caller_token(
            author,
            author,
            &["subscribe", "get"],
            &["system/subscription", "system/tree"],
        );

        let mut ctx = make_subscribe_ctx(author, token_hash, "user/inbox", included);
        ctx.caller_capability = Some(caller_cap);
        ctx.params = make_subscribe_params_with_payload("user/inbox", token_hash, true);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
    }

    #[tokio::test]
    async fn test_include_payload_false_does_not_require_get_grant() {
        // v3.13: subscribe-but-not-get + include_payload=false → 200.
        // Read-auth gate fires only when payload bundling is requested.
        let (handler, _) = make_handler();
        let author = Hash::compute("test", b"author-nopay");
        let token = make_delivery_token(author, author, None);
        let token_hash = token.content_hash;
        let included: std::collections::HashMap<Hash, Entity> =
            [(token_hash, token.clone())].into();

        let caller_cap = make_caller_token(
            author,
            author,
            &["subscribe"],
            &["system/subscription"],
        );

        let mut ctx = make_subscribe_ctx(author, token_hash, "user/inbox", included);
        ctx.caller_capability = Some(caller_cap);
        // include_payload omitted (== false): no read-auth required.
        ctx.params = make_subscribe_params_with_payload("user/inbox", token_hash, false);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
    }

    #[tokio::test]
    async fn test_include_payload_no_caller_cap_rejects_403() {
        // No caller_capability + include_payload=true → 403 (fail-closed).
        let (handler, _) = make_handler();
        let author = Hash::compute("test", b"author-nocap");
        let token = make_delivery_token(author, author, None);
        let token_hash = token.content_hash;
        let included: std::collections::HashMap<Hash, Entity> =
            [(token_hash, token.clone())].into();

        let mut ctx = make_subscribe_ctx(author, token_hash, "user/inbox", included);
        // caller_capability left None.
        ctx.params = make_subscribe_params_with_payload("user/inbox", token_hash, true);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_FORBIDDEN);
    }

    #[tokio::test]
    async fn test_sb1_intermediate_grant_succeeds() {
        // root: granter=A, grantee=B; child: granter=B, grantee=C, parent=root.
        // Author = B → matches at child level → InChain → 200.
        let (handler, _) = make_handler();
        let a = Hash::compute("test", b"identity-A");
        let b = Hash::compute("test", b"identity-B");
        let c = Hash::compute("test", b"identity-C");
        let root = make_delivery_token(a, b, None);
        let child = make_delivery_token(b, c, Some(root.content_hash));
        let token_hash = child.content_hash;
        let included: std::collections::HashMap<Hash, Entity> = [
            (root.content_hash, root.clone()),
            (token_hash, child.clone()),
        ]
        .into();
        let ctx = make_subscribe_ctx(b, token_hash, "user/inbox", included);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
    }
}
