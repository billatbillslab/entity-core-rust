//! The `system/relay` handler (§4) — `:forward`, `:put`, `:poll`, `:advertise`.
//!
//! Capability gating (§5.2 `relay-forward` / `relay-put` / `relay-poll` /
//! `relay-advertise`) is enforced at the dispatch layer against the envelope
//! capability, exactly as for every other handler — the handler body carries no
//! cap checks (matches REGISTRY / DISCOVERY). The relay constructs **no**
//! cap-chain link (§5.1); the carried inner envelope's signature + chain are
//! verified by the *destination*, never here.
//!
//! Envelope opacity (§9): the inner envelope rides in the EXECUTE's `included`
//! set as an [`Entity`] referenced by `envelope_inner`. Its `data` is the raw
//! inner bytes, preserved byte-for-byte by the wire codec. The handler stores
//! and forwards it **without decoding it** — Mode-F delivery goes through the
//! injected [`RelayForwarder`] which carries the opaque bytes onward.

use std::collections::HashMap;
use std::sync::Arc;

use entity_ecf::Value;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST,
};
use entity_store::{ContentStore, LocationIndex};

use crate::data::{ForwardRequest, ForwardResult, PollRequest, PollResult, PutResult, StoreEntry};
use crate::forwarder::{ForwardCtx, ForwardOutcome, RelayForwarder};
use crate::resolver::{InboxRelayResolver, NopInboxRelayResolver};
use crate::result::{error, ok_result};
use crate::store::ModeStore;
use crate::{
    advertise_path, inner_store_path, is_valid_namespace, store_entry_path,
    CODE_EXPIRED_ON_ARRIVAL, CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_NAMESPACE_INVALID,
    CODE_NO_INBOX_RELAY, CODE_NO_ROUTE, CODE_PUT_BY_MISMATCH, CODE_TTL_EXHAUSTED,
    CODE_UNKNOWN_OPERATION, FORWARD_STATUS_FORWARDED, FORWARD_STATUS_QUEUED_FALLBACK,
};

const STATUS_BAD_GATEWAY: u32 = 502;

pub struct RelayHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    peer_id: String,
    qualified_pattern: String,
    store: ModeStore,
    /// Mode-F outbound delivery. `None` → every destination is treated as
    /// unreachable and takes the §6.2.1 Mode-S fallback (the local floor).
    forwarder: Option<Arc<dyn RelayForwarder>>,
    /// §3.5 inbox-relay resolver (the MX lookup). Default is a no-op → the
    /// fallback uses the default convention (or `no_inbox_relay` if disabled).
    inbox_relay_resolver: Arc<dyn InboxRelayResolver>,
    /// §9.5 "MX-required" posture. When `true`, the §6.2.1 fallback returns
    /// `no_inbox_relay`/502 instead of using the default-convention namespace.
    /// Default `false` (default convention on).
    disable_default_fallback: bool,
}

impl RelayHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/relay", local_peer_id);
        Self {
            content_store,
            location_index,
            peer_id: local_peer_id,
            qualified_pattern,
            store: ModeStore::new(),
            forwarder: None,
            inbox_relay_resolver: Arc::new(NopInboxRelayResolver),
            disable_default_fallback: false,
        }
    }

    /// Inject the Mode-F outbound forwarder (wired in `core/peer` over the
    /// connection pool). Without it, Mode F falls back to Mode S (§6.2.1).
    pub fn with_forwarder(mut self, forwarder: Arc<dyn RelayForwarder>) -> Self {
        self.forwarder = Some(forwarder);
        self
    }

    /// Inject the §3.5 inbox-relay resolver (REGISTRY-backed in production).
    pub fn with_inbox_relay_resolver(mut self, resolver: Arc<dyn InboxRelayResolver>) -> Self {
        self.inbox_relay_resolver = resolver;
        self
    }

    /// Adopt the §9.5 "MX-required" posture: the §6.2.1 fallback surfaces
    /// `no_inbox_relay`/502 rather than using the default-convention namespace.
    pub fn with_disable_default_fallback(mut self, disable: bool) -> Self {
        self.disable_default_fallback = disable;
        self
    }

    // -----------------------------------------------------------------------
    // Mode S — :put (§3.2, §4.2)
    // -----------------------------------------------------------------------

    async fn handle_put(&self, ctx: &HandlerContext) -> HandlerResult {
        let entry = match StoreEntry::from_params(&ctx.params.data) {
            Ok(e) => e,
            Err(e) => return error(STATUS_BAD_REQUEST, CODE_INVALID_PARAMS, &e.to_string()),
        };

        if !is_valid_namespace(&entry.namespace) {
            return error(
                STATUS_BAD_REQUEST,
                CODE_NAMESPACE_INVALID,
                &format!("malformed namespace path: {:?}", entry.namespace),
            );
        }

        // §2.2 / §3.2 put_by is placement-identity: on a wire :put it MUST equal
        // the **authenticated connection peer** (the session peer), NOT the
        // wire-author — on a cross-peer relay dispatch the placer is whoever
        // connected, not whoever signed the inner request. Authorship (the
        // inner-envelope signature) is never consulted here.
        //
        // Carve-out (matches Go §4.2): when there is no session peer (in-process
        // / internal dispatch, e.g. the §6.2.1 fallback's direct store), the
        // check is skipped — the literal-spec rule binds "on a wire :put."
        match ctx.session_peer_id.as_deref() {
            Some(caller) if caller == entry.put_by => {}
            Some(caller) => {
                return error(
                    STATUS_BAD_REQUEST,
                    CODE_PUT_BY_MISMATCH,
                    &format!(
                        "put_by ({}) != authenticated connection peer ({})",
                        entry.put_by, caller
                    ),
                );
            }
            None => {} // no session peer → internal/in-process; carve-out
        }

        // §4.3 expired_on_arrival is 400 (creation-side dead-on-arrival), not
        // 410 — nothing was ever stored, so no resource is Gone.
        let now = now_ms();
        if matches!(entry.expires_at, Some(e) if e <= now) {
            return error(
                STATUS_BAD_REQUEST,
                CODE_EXPIRED_ON_ARRIVAL,
                "expires_at already past at put time",
            );
        }

        self.store_entry(ctx, &entry, &entry.namespace)
    }

    /// Store the inner envelope (opaque) + the store-entry, index at the §3.2
    /// path, and append to the relay-owned poll log. Shared by `:put` and the
    /// §6.2.1 Mode-F fallback. Returns a `put-result`.
    fn store_entry(
        &self,
        ctx: &HandlerContext,
        entry: &StoreEntry,
        namespace: &str,
    ) -> HandlerResult {
        // Persist the opaque inner envelope so the poller can fetch it (§4.2
        // two-hop fetch). It rides in the EXECUTE `included` set, held as raw
        // bytes — stored verbatim, never decoded (§9).
        if let Some(inner) = ctx.included.get(&entry.envelope_inner) {
            let inner_hash = match self.content_store.put(inner.clone()) {
                Ok(h) => h,
                Err(e) => {
                    return error(
                        entity_handler::STATUS_INTERNAL_ERROR,
                        "inner_store_failed",
                        &e.to_string(),
                    );
                }
            };
            // Relay receive-side fetch-surface ruling (§3.2): tree-bind
            // the inner under the same namespace subtree as the store-entry so the
            // receiver fetches it with `tree:get` — `system/content` is NOT a relay
            // receive-side dependency, and the namespace-scoped tree-read cap (§5)
            // governs both reads. path→hash; the bytes still live once in the
            // content store (dedup preserved across namespaces).
            let inner_path = inner_store_path(&self.peer_id, namespace, &inner_hash.to_hex());
            self.location_index.set(&inner_path, inner_hash);
        }

        // The stored entry IS the request entity (§4.2 — request IS a
        // store-entry); store it verbatim so `entry_hash` is the caller's hash
        // and bytes are preserved. For the fallback path the relay authors a
        // fresh store-entry (put_by = relay), so re-encode there.
        let store_entry_entity = match entry.to_entity() {
            Ok(e) => e,
            Err(e) => {
                return error(
                    entity_handler::STATUS_INTERNAL_ERROR,
                    "store_entry_encode_failed",
                    &e.to_string(),
                )
            }
        };
        let entry_hash = match self.content_store.put(store_entry_entity) {
            Ok(h) => h,
            Err(e) => {
                return error(
                    entity_handler::STATUS_INTERNAL_ERROR,
                    "store_failed",
                    &e.to_string(),
                )
            }
        };

        let path = store_entry_path(&self.peer_id, namespace, &entry_hash.to_hex());
        self.location_index.set(&path, entry_hash);
        self.store.put(namespace, entry_hash, entry.expires_at);

        let result = PutResult {
            stored_at: path,
            entry_hash,
            expires_at: entry.expires_at,
        };
        match result.to_entity() {
            Ok(e) => ok_result(e, HashMap::new()),
            Err(e) => error(
                entity_handler::STATUS_INTERNAL_ERROR,
                "result_encode_failed",
                &e.to_string(),
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Mode S — :poll (§4.2)
    // -----------------------------------------------------------------------

    async fn handle_poll(&self, ctx: &HandlerContext) -> HandlerResult {
        let req = match PollRequest::from_params(&ctx.params.data) {
            Ok(r) => r,
            Err(e) => return error(STATUS_BAD_REQUEST, CODE_INVALID_PARAMS, &e.to_string()),
        };
        if !is_valid_namespace(&req.namespace) {
            return error(
                STATUS_BAD_REQUEST,
                CODE_NAMESPACE_INVALID,
                &format!("malformed namespace path: {:?}", req.namespace),
            );
        }

        // Opaque relay-owned cursor: 8-byte BE seq. A malformed cursor restarts
        // from the beginning rather than erroring (lenient; the cursor is ours).
        let since = req.since.as_deref().map(crate::data::parse_cursor);
        let limit = req.limit.map(|l| l as usize);

        let page = self.store.poll(&req.namespace, since, limit, now_ms());
        let result = PollResult::new(page.entries, page.cursor, page.has_more);
        match result.to_entity() {
            Ok(e) => ok_result(e, HashMap::new()),
            Err(e) => error(
                entity_handler::STATUS_INTERNAL_ERROR,
                "result_encode_failed",
                &e.to_string(),
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Mode F — :forward (§3.1, §3.1.1, §6.2.1)
    // -----------------------------------------------------------------------

    /// EXTENSION-ROUTE §3 table read — fires **only** when a `forward-request`
    /// has no source route and no `next_hop` (precedence: source route > table >
    /// direct; cross-impl trap #5 — consulting the table when a path is given
    /// would override the originator's intent). The relay performs the read
    /// (enumerate the local `system/route/*` subtree, decode each entity); ROUTE
    /// owns the match semantics ([`entity_route::resolve`]). Returns the chosen
    /// next-hop peer-id (the destination itself for a `deliver` route → terminal),
    /// or `None` on no match → the caller surfaces `no_route`/502.
    fn resolve_from_table(&self, destination: &str) -> Option<String> {
        let prefix = format!("/{}/{}", self.peer_id, entity_route::ROUTE_PREFIX);
        let listed = self.location_index.list(&prefix);
        if listed.is_empty() {
            return None;
        }
        let routes: Vec<entity_route::RouteData> = listed
            .into_iter()
            .filter_map(|e| self.content_store.get(&e.hash))
            .filter_map(|ent| entity_route::RouteData::from_entity(&ent).ok())
            .collect();

        match entity_route::resolve(&routes, destination, now_ms())? {
            // A `deliver` route makes this relay terminal: name the destination
            // as `next` so the §3.1.1 `next == destination` gate dispatches the
            // bare inner envelope.
            entity_route::RouteResolution::Deliver => Some(destination.to_string()),
            entity_route::RouteResolution::Forward(via) => Some(via),
        }
    }

    async fn handle_forward(&self, ctx: &HandlerContext) -> HandlerResult {
        let req = match ForwardRequest::from_params(&ctx.params.data) {
            Ok(r) => r,
            Err(e) => return error(STATUS_BAD_REQUEST, CODE_INVALID_PARAMS, &e.to_string()),
        };

        // §3.1: reject (fail-closed) if ttl_hops is 0 on receipt.
        if req.ttl_hops == 0 {
            return error(STATUS_BAD_REQUEST, CODE_TTL_EXHAUSTED, "ttl_hops reached 0");
        }
        let onward_ttl = req.ttl_hops - 1;

        // §3.1.1 per-hop next-hop algorithm — precedence:
        //   1. source route (`route`, non-empty)  → next = route[0], remaining = route[1:]
        //   2. `next_hop` shorthand                → next = next_hop, remaining = []
        //   3. route table (`EXTENSION-ROUTE` §3)  → exact/`*` match, metric, expiry
        //   4. else                                → no_route/502 (direct-or-no_route floor)
        // Cross-field invariant: when both `route` and `next_hop` are set,
        // `next_hop` MUST equal route[0] — else invalid_request/400 PRE-DISPATCH.
        let route = req.route.clone().unwrap_or_default();
        let (next_hop, remaining): (String, Vec<String>) = if !route.is_empty() {
            let head = route[0].clone();
            if let Some(nh) = &req.next_hop {
                if nh != &head {
                    return error(
                        STATUS_BAD_REQUEST,
                        CODE_INVALID_REQUEST,
                        &format!(
                            "next_hop ({}) MUST equal route[0] ({}) when both are set (§3.1.1)",
                            nh, head
                        ),
                    );
                }
            }
            (head, route[1..].to_vec())
        } else if let Some(nh) = req.next_hop.clone() {
            (nh, Vec::new())
        } else {
            // No source route, no explicit next_hop — consult the local route
            // table (EXTENSION-ROUTE §3). A `deliver` route yields the
            // destination itself (terminal); a `forward` route yields `via`.
            match self.resolve_from_table(&req.destination) {
                Some(next) => (next, Vec::new()),
                None => {
                    return error(
                        STATUS_BAD_GATEWAY,
                        CODE_NO_ROUTE,
                        "no source route, no next_hop, and no matching system/route entry (§3.1.1)",
                    );
                }
            }
        };

        // The inner envelope MUST ride in `included` to be forwardable (§9).
        let Some(inner) = ctx.included.get(&req.envelope_inner).cloned() else {
            return error(
                STATUS_BAD_REQUEST,
                CODE_INVALID_PARAMS,
                "envelope_inner not present in included set",
            );
        };

        // §3.1.1: terminal hop when next resolves to the destination.
        let is_terminal = next_hop == req.destination;

        let outcome = match &self.forwarder {
            Some(fwd) => {
                fwd.forward(ForwardCtx {
                    destination: &req.destination,
                    next_hop: &next_hop,
                    is_terminal,
                    ttl_hops: onward_ttl,
                    onward_route: &remaining,
                    inner: &inner,
                })
                .await
            }
            // No live transport wired → destination is unreachable; fall back.
            None => ForwardOutcome::Unreachable,
        };

        match outcome {
            ForwardOutcome::Forwarded { next_hop } => {
                let result = ForwardResult {
                    status: FORWARD_STATUS_FORWARDED.into(),
                    next_hop: Some(next_hop),
                    stored_at: None,
                };
                self.forward_result(result)
            }
            // §6.2.1 + §3.5 fallback resolution order:
            //   1. declared inbox-relay → highest-priority entry targeting us,
            //   2. default convention (namespace = destination peer_id), unless
            //      the MX-required posture disabled it,
            //   3. else no_inbox_relay/502 (fail-closed, never silent).
            // put_by = the relay (placement-identity); authorship stays the
            // inner-envelope signature (§3.2 — the two diverge here by design).
            ForwardOutcome::Unreachable => {
                let namespace = match self
                    .inbox_relay_resolver
                    .resolve(&req.destination)
                    .await
                    .and_then(|decl| decl.namespace_for_relay(&self.peer_id))
                {
                    Some(ns) => ns, // (1) declared, targets us
                    None if !self.disable_default_fallback => req.destination.clone(), // (2)
                    None => {
                        // (3) MX-required + no declaration targeting us.
                        return error(
                            STATUS_BAD_GATEWAY,
                            CODE_NO_INBOX_RELAY,
                            "destination unreachable and no usable inbox-relay declaration",
                        );
                    }
                };

                let fallback_entry = StoreEntry {
                    namespace: namespace.clone(),
                    expires_at: None,
                    put_by: self.peer_id.clone(),
                    envelope_inner: req.envelope_inner,
                };
                // store_entry returns a put-result; we re-shape to a
                // forward-result {queued-fallback}. Reuse the storage path so
                // the inner envelope + log entry land identically to a wire :put.
                let put = self.store_entry(ctx, &fallback_entry, &namespace);
                if put.status != entity_handler::STATUS_OK {
                    return put; // surface the storage error fail-closed
                }
                let result = ForwardResult {
                    status: FORWARD_STATUS_QUEUED_FALLBACK.into(),
                    next_hop: None,
                    stored_at: Some(namespace),
                };
                self.forward_result(result)
            }
        }
    }

    fn forward_result(&self, result: ForwardResult) -> HandlerResult {
        match result.to_entity() {
            Ok(e) => ok_result(e, HashMap::new()),
            Err(e) => error(
                entity_handler::STATUS_INTERNAL_ERROR,
                "result_encode_failed",
                &e.to_string(),
            ),
        }
    }

    // -----------------------------------------------------------------------
    // All — :advertise (§4.1)
    // -----------------------------------------------------------------------

    async fn handle_advertise(&self, ctx: &HandlerContext) -> HandlerResult {
        // The advertise request params ARE the advertise data. The relay stores
        // the entity at system/relay/advertise/{relay_peer_id} (= self). The
        // V7 §5.2 signature is the operator's authoring concern (reachable at
        // the invariant pointer); the handler persists + indexes the entity.
        let advertise = match crate::data::AdvertiseData::from_entity(&ctx.params) {
            Ok(a) => a,
            Err(e) => return error(STATUS_BAD_REQUEST, CODE_INVALID_PARAMS, &e.to_string()),
        };
        let entity = match advertise.to_entity() {
            Ok(e) => e,
            Err(e) => {
                return error(
                    entity_handler::STATUS_INTERNAL_ERROR,
                    "advertise_encode_failed",
                    &e.to_string(),
                )
            }
        };
        let hash = match self.content_store.put(entity) {
            Ok(h) => h,
            Err(e) => {
                return error(
                    entity_handler::STATUS_INTERNAL_ERROR,
                    "store_failed",
                    &e.to_string(),
                )
            }
        };
        let path = advertise_path(&self.peer_id, &self.peer_id);
        self.location_index.set(&path, hash);

        let fields = vec![
            (entity_ecf::text("advertised"), Value::Bool(true)),
            (
                entity_ecf::text("advertise_hash"),
                Value::Bytes(hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("path"), entity_ecf::text(&path)),
        ];
        let result = entity_entity::Entity::new(
            entity_types::TYPE_PROTOCOL_STATUS,
            entity_ecf::to_ecf(&Value::Map(fields)),
        )
        .expect("status entity");
        ok_result(result, HashMap::new())
    }

}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Handler for RelayHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "forward" => Ok(self.handle_forward(ctx).await),
            "put" => Ok(self.handle_put(ctx).await),
            "poll" => Ok(self.handle_poll(ctx).await),
            "advertise" => Ok(self.handle_advertise(ctx).await),
            other => Ok(error(
                STATUS_BAD_REQUEST,
                CODE_UNKNOWN_OPERATION,
                &format!("unknown relay op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "relay"
    }

    fn operations(&self) -> &[&str] {
        &["forward", "put", "poll", "advertise"]
    }
}

fn now_ms() -> i64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
