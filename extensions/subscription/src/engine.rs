//! Subscription engine — processes tree change events and delivers notifications.
//!
//! Architecture: The sync `on_tree_change()` hook (position 8) performs all
//! matching, limit checking, token validation, and notification entity
//! construction synchronously.  Pre-built `DeliveryWork` items are sharded
//! by `subscription_id` across `DELIVERY_SHARD_COUNT` mpsc channels.  The
//! async `start()` spawns one delivery worker per shard so cross-subscription
//! deliveries run in parallel while within-subscription FIFO ordering is
//! preserved (EXTENSION-SUBSCRIPTION v3.15 §5.2: within-sub deliveries MUST
//! arrive in tree-change order; cross-sub parallelism is impl-defined and
//! shard-by-`subscription_id` is the recommended shape per workbench-go's
//! K=4 → 3.8× saturation measurement).

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash as _, Hasher};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use web_time::Instant;

use entity_capability::CapabilityToken;
use entity_entity::Entity;
use entity_handler::HandlerError;
use entity_hash::Hash;
use entity_store::{ChangeType, ContentStore, ExecutionContext, LocationIndex, SyncTreeHook, TreeChangeEvent};

// Platform-aware task spawning: tokio::spawn on native, wasm_bindgen_futures::spawn_local on WASM.
// On native, the start() method uses tokio::spawn directly for JoinHandle return type,
// so this function is only called from the WASM cfg path.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn spawn_task<F: std::future::Future<Output = ()> + Send + 'static>(f: F) {
    tokio::spawn(f);
}
#[cfg(target_arch = "wasm32")]
fn spawn_task<F: std::future::Future<Output = ()> + 'static>(f: F) {
    wasm_bindgen_futures::spawn_local(f);
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A request to deliver a notification via inbox.
#[derive(Debug, Clone)]
pub struct DeliveryRequest {
    pub request_id: String,
    pub deliver_uri: String,
    pub deliver_token: Entity,
    pub params: Entity,
    pub resource: Option<entity_capability::ResourceTarget>,
    /// Entities to bundle into the delivery envelope's `included` map.
    /// Populated when the subscription opted in via `include_payload` and
    /// the changed entity is locally available — collapses the mirror recipe
    /// from a 3-hop chain (notify → cross-peer GET → response) to a single hop.
    /// See PROPOSAL-CONVERGENT-MIRRORING §2.
    pub included: HashMap<Hash, Entity>,
}

/// Internal work item queued from the sync hook to the async delivery loop.
pub(crate) struct DeliveryWork {
    subscription_id: String,
    request: DeliveryRequest,
    /// Chain causality from the source tree change (per EXTENSION-SUBSCRIPTION
    /// §4.5). Carried so that terminal delivery failures can bind a chain-error
    /// marker at the spec'd path per §4.7. Empty when the originating tree
    /// change carried no chain context.
    chain_id: String,
}

/// The delivery function type — injected by peer setup.
#[cfg(not(target_arch = "wasm32"))]
pub type DeliverFn = Arc<
    dyn Fn(DeliveryRequest) -> Pin<Box<dyn Future<Output = Result<(), HandlerError>> + Send>>
        + Send
        + Sync,
>;

#[cfg(target_arch = "wasm32")]
pub type DeliverFn = Arc<
    dyn Fn(DeliveryRequest) -> Pin<Box<dyn Future<Output = Result<(), HandlerError>>>>
        + Send
        + Sync,
>;

/// Subscription data stored in the engine.
#[derive(Debug, Clone)]
pub struct SubscriptionData {
    pub subscription_id: String,
    pub pattern: String,
    pub events: Vec<String>,
    pub deliver_uri: String,
    pub deliver_operation: String,
    pub subscriber_identity: Hash,
    pub deliver_token: Hash,
    pub created_at: u64,
    pub limits: Option<SubscriptionLimits>,
    /// Subscriber-opt-in: when true, the server bundles the changed entity
    /// into the delivery envelope's `included` map so the subscriber has the
    /// bytes atomically with the notification (no separate cross-peer GET).
    /// PROPOSAL-CONVERGENT-MIRRORING §2.
    pub include_payload: bool,
}

#[derive(Debug, Clone)]
pub struct SubscriptionLimits {
    pub max_events: Option<u64>,
    pub max_duration_ms: Option<u64>,
    pub rate_limit: Option<u64>,
}

struct ActiveSubscription {
    data: SubscriptionData,
    delivered_count: u64,
    last_delivery: Option<Instant>,
    created_at: Instant,
}

/// Fact-tuple captured when the engine matches a subscription against a
/// tree change and constructs a notification entity. Per GUIDE-INSPECTABILITY
/// v1.2 §2.1 #6 ("Notification-emission event").
///
/// Observer-only: hooks MUST NOT retain `&EmitEvent` past return.
#[derive(Debug, Clone)]
pub struct EmitEvent {
    pub subscription_id: String,
    pub source_change_uri: String,
    pub notification_hash: Hash,
    pub timestamp_ms: u64,
}

/// Fact-tuple captured at the outcome of a delivery dispatch attempt.
/// Per GUIDE-INSPECTABILITY v1.2 §2.1 #7 ("Notification-delivery event").
///
/// `status` is `STATUS_OK` on success; the underlying `HandlerError` text
/// is surfaced via `error_code` on failure. Cap-token + signature material
/// is intentionally NOT exposed here (per security audit §2.1 #c).
#[derive(Debug, Clone)]
pub struct DeliverEvent {
    pub subscription_id: String,
    pub notification_hash: Hash,
    pub deliver_uri: String,
    pub status: u32,
    pub error_code: Option<String>,
    pub timestamp_ms: u64,
}

/// Observe-only emit-event callback type.
pub type EmitHookFn = Arc<dyn Fn(&EmitEvent) + Send + Sync>;

/// Observe-only deliver-event callback type.
pub type DeliverHookFn = Arc<dyn Fn(&DeliverEvent) + Send + Sync>;

/// Outcome of `check_limits`. Failure variants carry the §4.7 `{reason}`
/// code so the sync hook can bind a chain-error marker.
#[derive(Debug, Clone, Copy)]
enum LimitAction {
    Allow,
    /// Single delivery suppressed (e.g. `rate_limited`); subscription persists.
    Deny(&'static str),
    /// Subscription terminates (e.g. `max_events_reached`, `max_duration_reached`).
    Terminate(&'static str),
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Number of delivery worker shards. Deliveries are routed to a shard by
/// `hash(subscription_id) % DELIVERY_SHARD_COUNT`, so within-subscription
/// FIFO ordering is preserved (single mpsc queue per shard, single worker
/// consuming) while cross-subscription deliveries run concurrently across
/// shards. Matches workbench-go's K=4 measurement (3.8× scaling on cross-
/// peer saturation per EXTENSION-SUBSCRIPTION v3.15 §5.2 routing).
pub const DELIVERY_SHARD_COUNT: usize = 4;

/// The subscription engine that processes events and delivers notifications.
///
/// Matching and notification construction happen synchronously in
/// `on_tree_change()` (SyncTreeHook position 8).  Delivery happens
/// asynchronously in `start()` via a pool of `DELIVERY_SHARD_COUNT`
/// workers, each draining an independent mpsc receiver. Work items are
/// routed to a shard by `hash(subscription_id) % DELIVERY_SHARD_COUNT`,
/// so a given subscription's deliveries are always serialized through
/// the same worker (preserves within-sub ordering) while distinct
/// subscriptions hash-distribute across workers (enables cross-sub
/// parallelism). See v3.15 §5.2.
pub struct Engine {
    subscriptions: RwLock<HashMap<String, ActiveSubscription>>,
    path_index: RwLock<HashMap<String, Vec<String>>>,
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    pub deliver: RwLock<Option<DeliverFn>>,
    local_peer_id: String,
    /// One sender per shard. The sync hook computes `shard_for(sub_id)` and
    /// sends to the corresponding sender.
    delivery_txs: Vec<tokio::sync::mpsc::UnboundedSender<DeliveryWork>>,
    /// One receiver per shard, taken once by `start()`. Protected by
    /// Mutex<Option<>> so that only one `start()` call owns them.
    delivery_rxs: Mutex<Option<Vec<tokio::sync::mpsc::UnboundedReceiver<DeliveryWork>>>>,
    /// Observe-only emit hooks per GUIDE-INSPECTABILITY v1.2 §2.1 #6.
    /// Fired synchronously inside `on_tree_change` after the notification
    /// entity is built and before the `DeliveryWork` is enqueued.
    emit_hooks: RwLock<Vec<(String, EmitHookFn)>>,
    /// Observe-only deliver hooks per GUIDE-INSPECTABILITY v1.2 §2.1 #7.
    /// Fired inside the async delivery worker around `deliver_fn.await`,
    /// once per outcome (Ok or Err).
    deliver_hooks: RwLock<Vec<(String, DeliverHookFn)>>,
}

/// Compute the shard a subscription_id routes to. Uses std `DefaultHasher`
/// for distribution only — not security-relevant, no need for cryptographic
/// hashing.
fn shard_for(subscription_id: &str) -> usize {
    let mut h = DefaultHasher::new();
    subscription_id.hash(&mut h);
    (h.finish() as usize) % DELIVERY_SHARD_COUNT
}

impl Engine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let mut delivery_txs = Vec::with_capacity(DELIVERY_SHARD_COUNT);
        let mut delivery_rxs = Vec::with_capacity(DELIVERY_SHARD_COUNT);
        for _ in 0..DELIVERY_SHARD_COUNT {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            delivery_txs.push(tx);
            delivery_rxs.push(rx);
        }
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            path_index: RwLock::new(HashMap::new()),
            content_store,
            location_index,
            deliver: RwLock::new(None),
            local_peer_id,
            delivery_txs,
            delivery_rxs: Mutex::new(Some(delivery_rxs)),
            emit_hooks: RwLock::new(Vec::new()),
            deliver_hooks: RwLock::new(Vec::new()),
        }
    }

    /// Register an observe-only emit hook (GUIDE-INSPECTABILITY v1.2 §2.1 #6 /
    /// §2.3 "Subscription tracer"). Fires synchronously inside
    /// `on_tree_change` after the notification entity is constructed and
    /// before the delivery is enqueued, once per matched subscription.
    ///
    /// Hooks live on the engine rather than on `PeerBuilder` per the
    /// DAG-discipline finding in the L1 review §2.5 (mirrors core-go §2).
    pub fn add_emit_hook(
        &self,
        name: impl Into<String>,
        f: impl Fn(&EmitEvent) + Send + Sync + 'static,
    ) {
        self.emit_hooks
            .write()
            .unwrap()
            .push((name.into(), Arc::new(f)));
    }

    /// Register an observe-only deliver hook (GUIDE-INSPECTABILITY v1.2 §2.1 #7).
    /// Fires inside the async delivery worker around `deliver_fn.await`,
    /// once per outcome — `Ok` (status = STATUS_OK, error_code = None) or
    /// `Err` (status = 0, error_code = classified transport code).
    pub fn add_deliver_hook(
        &self,
        name: impl Into<String>,
        f: impl Fn(&DeliverEvent) + Send + Sync + 'static,
    ) {
        self.deliver_hooks
            .write()
            .unwrap()
            .push((name.into(), Arc::new(f)));
    }

    /// Snapshot the emit-hook list for firing. Caller iterates over the
    /// returned Vec; lock is released immediately.
    fn snapshot_emit_hooks(&self) -> Vec<(String, EmitHookFn)> {
        self.emit_hooks.read().unwrap().clone()
    }

    /// Snapshot the deliver-hook list for firing.
    fn snapshot_deliver_hooks(&self) -> Vec<(String, DeliverHookFn)> {
        self.deliver_hooks.read().unwrap().clone()
    }

    /// Rebuild the routing index from durable tree state. Walks the
    /// `/{local_peer_id}/system/subscription/` prefix via the
    /// backend-agnostic `LocationIndex::list` API, decodes each
    /// `system/subscription` entity, and `register`s it.
    ///
    /// Without this call, persistent peers start with an empty routing
    /// index after restart and notifications silently drop until
    /// subscribers re-call subscribe (the bug that triggered the
    /// restart-equivalence work). Peer-builder invokes this once during
    /// construction so the post-restart engine behaves equivalently to
    /// a continuously-running one.
    ///
    /// Idempotent: re-registering an already-known subscription_id
    /// overwrites the engine entry (HashMap::insert semantics) but the
    /// path_index entry is append-only, so subsequent rebuilds would
    /// duplicate. This method is intended to be called once per build,
    /// before any runtime `register()` calls.
    pub fn load(&self) {
        let prefix = format!("/{}/system/subscription/", self.local_peer_id);
        let mut loaded = 0usize;
        for entry in self.location_index.list(&prefix) {
            let Some(entity) = self.content_store.get(&entry.hash) else {
                continue;
            };
            let Some(sub) = crate::decode_subscription_entity(&entity) else {
                continue;
            };
            self.register(sub);
            loaded += 1;
        }
        tracing::debug!(
            local_peer_id = %self.local_peer_id,
            loaded,
            "subscription engine routing index rebuilt from tree"
        );
    }

    /// Register a subscription in the engine.
    pub fn register(&self, sub: SubscriptionData) {
        let id = sub.subscription_id.clone();
        let pattern = sub.pattern.clone();

        self.subscriptions.write().unwrap().insert(
            id.clone(),
            ActiveSubscription {
                data: sub,
                delivered_count: 0,
                last_delivery: None,
                created_at: Instant::now(),
            },
        );

        self.path_index
            .write()
            .unwrap()
            .entry(pattern)
            .or_default()
            .push(id);
    }

    /// Remove a subscription from the engine.
    pub fn remove(&self, subscription_id: &str) {
        self.subscriptions.write().unwrap().remove(subscription_id);

        let mut index = self.path_index.write().unwrap();
        for ids in index.values_mut() {
            ids.retain(|id| id != subscription_id);
        }
        // Clean up empty entries
        index.retain(|_, ids| !ids.is_empty());
    }

    /// Find a renewal candidate: same subscriber + pattern + deliver_uri.
    pub fn find_renewal(
        &self,
        subscriber: Hash,
        pattern: &str,
        deliver_uri: &str,
    ) -> Option<String> {
        let subs = self.subscriptions.read().unwrap();
        for (id, sub) in subs.iter() {
            if sub.data.subscriber_identity == subscriber
                && sub.data.pattern == pattern
                && sub.data.deliver_uri == deliver_uri
            {
                return Some(id.clone());
            }
        }
        None
    }

    /// Start the async delivery worker pool.
    ///
    /// Takes the internal per-shard mpsc receivers (can only be called once)
    /// and spawns `DELIVERY_SHARD_COUNT` worker tasks, one per shard. Each
    /// worker consumes `DeliveryWork` produced by `on_tree_change()` for the
    /// subscriptions hashing to its shard, and performs network delivery via
    /// the configured `DeliverFn`. Cross-shard deliveries run concurrently;
    /// within-shard deliveries are FIFO (v3.15 §5.2 within-sub ordering).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn start(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        let rxs = self
            .delivery_rxs
            .lock()
            .unwrap()
            .take()
            .expect("subscription engine start() called more than once");
        let mut handles = Vec::with_capacity(rxs.len());
        for (shard, mut rx) in rxs.into_iter().enumerate() {
            let engine = self.clone();
            handles.push(tokio::spawn(async move {
                while let Some(work) = rx.recv().await {
                    engine.deliver_notification(work).await;
                }
                tracing::info!(
                    shard,
                    "subscription engine: delivery channel closed"
                );
            }));
        }
        handles
    }

    /// Start the async delivery worker pool (WASM). Same sharding shape as
    /// native; WASM has a single-threaded event loop, but the workers'
    /// independent `.await` points still let one shard make progress while
    /// another awaits a network response, restoring within-shard FIFO +
    /// cross-shard interleaving.
    #[cfg(target_arch = "wasm32")]
    pub fn start(self: &Arc<Self>) {
        let rxs = self
            .delivery_rxs
            .lock()
            .unwrap()
            .take()
            .expect("subscription engine start() called more than once");
        for (shard, mut rx) in rxs.into_iter().enumerate() {
            let engine = self.clone();
            spawn_task(async move {
                while let Some(work) = rx.recv().await {
                    engine.deliver_notification(work).await;
                }
                tracing::info!(
                    shard,
                    "subscription engine: delivery channel closed"
                );
            });
        }
    }
}

// ---------------------------------------------------------------------------
// SyncTreeHook — synchronous emit consumer (SYSTEM-COMPOSITION §2.2, position 8)
// ---------------------------------------------------------------------------

/// Subscription suppression threshold (SYSTEM-COMPOSITION §3.2).
/// At cascade depth >= 8, subscription suppresses same-peer notification delivery.
const CASCADE_DEPTH_SUBSCRIPTION_SUPPRESS: u32 = 8;

impl SyncTreeHook for Engine {
    fn on_tree_change(&self, event: &TreeChangeEvent, ctx: &mut ExecutionContext)
        -> Result<(), entity_store::CascadeHalt>
    {
        if ctx.cascade_depth >= CASCADE_DEPTH_SUBSCRIPTION_SUPPRESS {
            return Ok(());
        }

        // Self-guard: skip paths under the subscription handler's own prefix.
        // Prevents recursive notifications when subscription entities are written.
        let sub_prefix = format!("/{}/system/subscription/", self.local_peer_id);
        if event.path.starts_with(&sub_prefix) {
            return Ok(());
        }

        let event_name = match event.change_type {
            ChangeType::Created => "created",
            ChangeType::Modified => "updated",
            ChangeType::Deleted => "deleted",
        };

        let matching_ids = self.match_subscriptions(&event.path);
        if matching_ids.is_empty() {
            return Ok(());
        }

        tracing::debug!(
            path = %event.path,
            event = event_name,
            matching = matching_ids.len(),
            "subscription sync hook: processing event"
        );

        // Collect IDs that need termination (deferred to avoid holding locks during removal).
        let mut to_terminate = Vec::new();

        for sub_id in matching_ids {
            let sub_data = {
                let mut subs = self.subscriptions.write().unwrap();
                let sub = match subs.get_mut(&sub_id) {
                    Some(s) => s,
                    None => continue,
                };

                // Check event filter
                if !sub.data.events.contains(&event_name.to_string()) {
                    continue;
                }

                // Check limits
                let action = check_limits(
                    &sub.data.limits,
                    sub.delivered_count,
                    sub.created_at,
                    sub.last_delivery,
                );

                match action {
                    LimitAction::Terminate(reason) => {
                        let id = sub.data.subscription_id.clone();
                        let deliver_uri = sub.data.deliver_uri.clone();
                        drop(subs);
                        // EXTENSION-SUBSCRIPTION §4.7: limit-exceeded
                        // suppression terminating this subscription binds a
                        // chain-error marker so chain_trace can distinguish
                        // "terminated by policy" from silent drop.
                        crate::chain_error::write_lost_error_marker(
                            &self.content_store,
                            &self.location_index,
                            &self.local_peer_id,
                            ctx.chain_id.as_deref().unwrap_or(""),
                            &id,
                            &deliver_uri,
                            reason,
                            0,
                            crate::chain_error::capture_failure_timestamp_ms(),
                        );
                        to_terminate.push(id);
                        continue;
                    }
                    LimitAction::Deny(reason) => {
                        let id = sub.data.subscription_id.clone();
                        let deliver_uri = sub.data.deliver_uri.clone();
                        drop(subs);
                        // §4.7: this notification is suppressed (e.g.
                        // rate_limited) but the subscription continues.
                        crate::chain_error::write_lost_error_marker(
                            &self.content_store,
                            &self.location_index,
                            &self.local_peer_id,
                            ctx.chain_id.as_deref().unwrap_or(""),
                            &id,
                            &deliver_uri,
                            reason,
                            0,
                            crate::chain_error::capture_failure_timestamp_ms(),
                        );
                        continue;
                    }
                    LimitAction::Allow => {}
                }

                sub.data.clone()
            };

            // Validate delivery token exists in content store
            let deliver_token = match self.content_store.get(&sub_data.deliver_token) {
                Some(e) => e,
                None => {
                    // §4.7 capability rejection: token missing.
                    crate::chain_error::write_lost_error_marker(
                        &self.content_store,
                        &self.location_index,
                        &self.local_peer_id,
                        ctx.chain_id.as_deref().unwrap_or(""),
                        &sub_id,
                        &sub_data.deliver_uri,
                        crate::chain_error::REASON_CAPABILITY_DENIED,
                        403,
                        crate::chain_error::capture_failure_timestamp_ms(),
                    );
                    to_terminate.push(sub_id.clone());
                    continue;
                }
            };

            // Check token expiry
            if let Ok(cap) = CapabilityToken::from_entity(&deliver_token) {
                let now_ms = web_time::SystemTime::now()
                    .duration_since(web_time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                if let Some(expires) = cap.expires_at {
                    if now_ms > expires {
                        // §4.7 capability rejection: token expired.
                        crate::chain_error::write_lost_error_marker(
                            &self.content_store,
                            &self.location_index,
                            &self.local_peer_id,
                            ctx.chain_id.as_deref().unwrap_or(""),
                            &sub_id,
                            &sub_data.deliver_uri,
                            crate::chain_error::REASON_CAPABILITY_DENIED,
                            403,
                            crate::chain_error::capture_failure_timestamp_ms(),
                        );
                        to_terminate.push(sub_id.clone());
                        continue;
                    }
                }
            }

            // Build notification entity
            let notification_entity = match build_notification(
                &sub_data.subscription_id,
                event_name,
                &event.path,
                &event.hash,
                event.previous_hash.as_ref(),
            ) {
                Some(e) => e,
                None => continue,
            };

            // EXTENSION-SUBSCRIPTION §2.2 v3.14: bundle changed entity into
            // the delivery envelope's `included` map for subscribers that
            // opted in via include_payload. Normative semantics:
            //   - direct entity at notification.hash only (no closure)
            //   - removes (event.new_hash is None) bundle nothing
            //   - source-side resolution failure ⇒ deliver hash-only + debug
            //     log (never fail-stop); receiver MAY fall back to GET.
            let mut delivery_included: HashMap<Hash, Entity> = HashMap::new();
            if sub_data.include_payload {
                if let Some(new_hash) = event.new_hash {
                    match self.content_store.get(&new_hash) {
                        Some(entity) => {
                            delivery_included.insert(new_hash, entity);
                        }
                        None => {
                            tracing::debug!(
                                subscription_id = %sub_id,
                                path = %event.path,
                                hash = %new_hash,
                                "include_payload: source-side resolution miss — \
                                 delivering hash-only (EXTENSION-SUBSCRIPTION v3.14 §2.2)"
                            );
                        }
                    }
                }
            }

            let notification_hash = notification_entity.content_hash;
            let request = DeliveryRequest {
                request_id: format!("notif-{}-{}", sub_id, now_nanos()),
                deliver_uri: sub_data.deliver_uri.clone(),
                deliver_token,
                params: notification_entity,
                resource: Some(entity_capability::ResourceTarget {
                    targets: vec![sub_data.deliver_uri.clone()],
                    exclude: vec![],
                }),
                included: delivery_included,
            };

            // GUIDE-INSPECTABILITY v1.2 §2.1 #6 emit hook. Fires after the
            // notification entity is built and before delivery is queued,
            // observer-only; cannot affect dispatch.
            let emit_hooks = self.snapshot_emit_hooks();
            if !emit_hooks.is_empty() {
                let emit_event = EmitEvent {
                    subscription_id: sub_id.clone(),
                    source_change_uri: event.path.clone(),
                    notification_hash,
                    timestamp_ms: crate::chain_error::capture_failure_timestamp_ms(),
                };
                for (_name, hook) in &emit_hooks {
                    hook(&emit_event);
                }
            }

            tracing::debug!(
                subscription_id = %sub_id,
                deliver_uri = %sub_data.deliver_uri,
                event = event_name,
                path = %event.path,
                "subscription sync hook: queuing notification for delivery"
            );

            // Queue for async delivery on the shard owning this
            // subscription_id (preserves within-sub FIFO ordering per
            // v3.15 §5.2; distributes load across DELIVERY_SHARD_COUNT
            // workers). If the receiver is dropped (engine shutting
            // down), silently discard — this is non-critical.
            //
            // chain_id is propagated from the source change's
            // ExecutionContext per §4.5 so that terminal delivery failures
            // can bind a §4.7 chain-error marker at the correct path.
            let shard = shard_for(&sub_id);
            let _ = self.delivery_txs[shard].send(DeliveryWork {
                subscription_id: sub_id,
                request,
                chain_id: ctx.chain_id.clone().unwrap_or_default(),
            });
        }

        // Terminate subscriptions outside the matching loop (avoids lock contention).
        for id in to_terminate {
            self.terminate_subscription(&id);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "subscription/notifier"
    }

    fn handler_pattern(&self) -> &str {
        "system/subscription"
    }
}

impl Engine {
    /// Perform async delivery of a single notification.
    pub(crate) async fn deliver_notification(&self, work: DeliveryWork) {
        let deliver_fn = {
            let guard = self.deliver.read().unwrap();
            match guard.as_ref() {
                Some(f) => f.clone(),
                None => return, // no delivery function configured yet
            }
        };

        tracing::debug!(
            subscription_id = %work.subscription_id,
            deliver_uri = %work.request.deliver_uri,
            "subscription engine: delivering notification"
        );

        let deliver_uri = work.request.deliver_uri.clone();
        let notification_hash = work.request.params.content_hash;
        let deliver_hooks = self.snapshot_deliver_hooks();
        match deliver_fn(work.request).await {
            Ok(()) => {
                tracing::debug!(
                    subscription_id = %work.subscription_id,
                    "subscription engine: delivery succeeded"
                );
                let mut subs = self.subscriptions.write().unwrap();
                if let Some(sub) = subs.get_mut(&work.subscription_id) {
                    sub.delivered_count += 1;
                    sub.last_delivery = Some(Instant::now());
                }
                drop(subs);
                // §2.1 #7 deliver hook — success arm.
                if !deliver_hooks.is_empty() {
                    let event = DeliverEvent {
                        subscription_id: work.subscription_id.clone(),
                        notification_hash,
                        deliver_uri: deliver_uri.clone(),
                        status: entity_handler::STATUS_OK,
                        error_code: None,
                        timestamp_ms: crate::chain_error::capture_failure_timestamp_ms(),
                    };
                    for (_name, hook) in &deliver_hooks {
                        hook(&event);
                    }
                }
            }
            Err(e) => {
                let err_text = e.to_string();
                tracing::warn!(
                    subscription_id = %work.subscription_id,
                    error = %err_text,
                    "subscription engine: delivery failed"
                );
                // EXTENSION-SUBSCRIPTION §4.7: bind a `lost` chain-error
                // marker so `chain_trace` can distinguish terminal
                // delivery failure from silent drop. Classification per
                // V7 §6.12; mirrors continuation §3.10.5.
                let reason = crate::chain_error::classify_transport_failure(&err_text);
                crate::chain_error::write_lost_error_marker(
                    &self.content_store,
                    &self.location_index,
                    &self.local_peer_id,
                    &work.chain_id,
                    &work.subscription_id,
                    &deliver_uri,
                    reason,
                    0,
                    crate::chain_error::capture_failure_timestamp_ms(),
                );
                // §2.1 #7 deliver hook — failure arm.
                if !deliver_hooks.is_empty() {
                    let event = DeliverEvent {
                        subscription_id: work.subscription_id.clone(),
                        notification_hash,
                        deliver_uri,
                        status: 0,
                        error_code: Some(reason.to_string()),
                        timestamp_ms: crate::chain_error::capture_failure_timestamp_ms(),
                    };
                    for (_name, hook) in &deliver_hooks {
                        hook(&event);
                    }
                }
            }
        }
    }

    /// Find subscriptions matching a path.
    fn match_subscriptions(&self, path: &str) -> Vec<String> {
        let index = self.path_index.read().unwrap();
        let mut results = Vec::new();

        for (pattern, ids) in index.iter() {
            if pattern_matches(pattern, path) {
                results.extend(ids.iter().cloned());
            }
        }
        results
    }

    fn terminate_subscription(&self, id: &str) {
        self.remove(id);
        let path = format!("/{}/system/subscription/{}", self.local_peer_id, id);
        self.location_index.remove(&path);
    }
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

fn pattern_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path.starts_with(prefix) && path.len() > prefix.len();
    }
    pattern == path
}

// ---------------------------------------------------------------------------
// Limit checking
// ---------------------------------------------------------------------------

fn check_limits(
    limits: &Option<SubscriptionLimits>,
    delivered_count: u64,
    created_at: Instant,
    last_delivery: Option<Instant>,
) -> LimitAction {
    let limits = match limits {
        Some(l) => l,
        None => return LimitAction::Allow,
    };

    // max_events
    if let Some(max) = limits.max_events {
        if delivered_count >= max {
            return LimitAction::Terminate(crate::chain_error::REASON_MAX_EVENTS_REACHED);
        }
    }

    // max_duration_ms
    if let Some(max_ms) = limits.max_duration_ms {
        let elapsed = created_at.elapsed().as_millis() as u64;
        if elapsed >= max_ms {
            return LimitAction::Terminate(crate::chain_error::REASON_MAX_DURATION_REACHED);
        }
    }

    // rate_limit (per minute)
    if let Some(rate) = limits.rate_limit {
        if rate > 0 {
            if let Some(last) = last_delivery {
                let min_interval_ms = 60_000 / rate;
                if last.elapsed().as_millis() < min_interval_ms as u128 {
                    return LimitAction::Deny(crate::chain_error::REASON_RATE_LIMITED);
                }
            }
        }
    }

    LimitAction::Allow
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_notification(
    subscription_id: &str,
    event: &str,
    uri: &str,
    hash: &Hash,
    previous_hash: Option<&Hash>,
) -> Option<Entity> {
    let mut fields = vec![
        (entity_ecf::text("event"), entity_ecf::text(event)),
        (
            entity_ecf::text("hash"),
            entity_ecf::Value::Bytes(hash.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("subscription_id"),
            entity_ecf::text(subscription_id),
        ),
        (entity_ecf::text("uri"), entity_ecf::text(uri)),
    ];
    if let Some(prev) = previous_hash {
        fields.push((
            entity_ecf::text("previous_hash"),
            entity_ecf::Value::Bytes(prev.to_bytes().to_vec()),
        ));
    }
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    Entity::new("system/protocol/inbox/notification", data).ok()
}

fn now_nanos() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn make_engine() -> Arc<Engine> {
        Arc::new(Engine::new(
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
            "test_peer".to_string(),
        ))
    }

    /// Drain every shard's delivery receiver and return the work items in
    /// shard order. Takes the shard receivers exclusively (engine is no
    /// longer drivable by `start()` afterwards) — single-shot test helper.
    fn drain_all(engine: &Engine) -> Vec<DeliveryWork> {
        let rxs = engine
            .delivery_rxs
            .lock()
            .unwrap()
            .take()
            .expect("delivery_rxs already taken");
        let mut out = Vec::new();
        for mut rx in rxs {
            while let Ok(w) = rx.try_recv() {
                out.push(w);
            }
        }
        out
    }

    fn make_sub_data(id: &str, pattern: &str) -> SubscriptionData {
        SubscriptionData {
            subscription_id: id.to_string(),
            pattern: pattern.to_string(),
            events: vec!["created".into(), "updated".into(), "deleted".into()],
            deliver_uri: "user/inbox".to_string(),
            deliver_operation: "receive".to_string(),
            subscriber_identity: Hash::zero(),
            deliver_token: Hash::zero(),
            created_at: 0,
            limits: None,
            include_payload: false,
        }
    }

    #[test]
    fn test_register_remove() {
        let engine = make_engine();
        engine.register(make_sub_data("sub-1", "app/*"));
        assert!(engine.subscriptions.read().unwrap().contains_key("sub-1"));

        engine.remove("sub-1");
        assert!(!engine.subscriptions.read().unwrap().contains_key("sub-1"));
        assert!(engine.path_index.read().unwrap().get("app/*").is_none());
    }

    #[test]
    fn test_find_renewal() {
        let engine = make_engine();
        let mut sub = make_sub_data("sub-1", "app/data");
        sub.subscriber_identity = Hash::compute("t", b"alice");
        sub.deliver_uri = "alice/inbox".to_string();
        engine.register(sub);

        let found = engine.find_renewal(Hash::compute("t", b"alice"), "app/data", "alice/inbox");
        assert_eq!(found, Some("sub-1".to_string()));

        let not_found = engine.find_renewal(Hash::compute("t", b"bob"), "app/data", "alice/inbox");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_pattern_matching() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("app/*", "app/data"));
        assert!(pattern_matches("app/*", "app/data/nested"));
        assert!(!pattern_matches("app/*", "app")); // must have something after prefix
        assert!(pattern_matches("app/data", "app/data"));
        assert!(!pattern_matches("app/data", "app/other"));
    }

    #[test]
    fn test_pattern_matching_absolute() {
        // After leading-slash convention, both patterns and paths are absolute
        assert!(pattern_matches("*", "/peer/system/tree"));
        assert!(pattern_matches("/peer/system/*", "/peer/system/tree"));
        assert!(pattern_matches("/peer/system/*", "/peer/system/tree/foo"));
        assert!(!pattern_matches("/peer/system/*", "/peer/system"));
        assert!(pattern_matches("/peer/system/tree", "/peer/system/tree"));
        assert!(!pattern_matches("/peer/system/tree", "/other/system/tree"));
    }

    #[test]
    fn test_match_subscriptions() {
        let engine = make_engine();
        engine.register(make_sub_data("sub-1", "app/*"));
        engine.register(make_sub_data("sub-2", "app/data"));
        engine.register(make_sub_data("sub-3", "other/*"));

        let matches = engine.match_subscriptions("app/data");
        assert_eq!(matches.len(), 2); // sub-1 (wildcard) + sub-2 (exact)

        let matches2 = engine.match_subscriptions("other/thing");
        assert_eq!(matches2.len(), 1);
    }

    #[test]
    fn test_check_limits_no_limits() {
        let action = check_limits(&None, 0, Instant::now(), None);
        assert!(matches!(action, LimitAction::Allow));
    }

    #[test]
    fn test_check_limits_max_events_terminate() {
        let limits = Some(SubscriptionLimits {
            max_events: Some(5),
            max_duration_ms: None,
            rate_limit: None,
        });
        let action = check_limits(&limits, 5, Instant::now(), None);
        assert!(matches!(action, LimitAction::Terminate(_)));
    }

    #[test]
    fn a2_emit_hook_fires_on_matched_subscription() {
        // GUIDE-INSPECTABILITY v1.2 §2.1 #6: emit hook fires once per
        // matched subscription after notification entity is built.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(Engine::new(store.clone(), index.clone(), "peer1".to_string()));

        let token_entity = Entity::new(
            "system/capability/token",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("granter"),
                    entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec()),
                ),
                (
                    entity_ecf::text("grantee"),
                    entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec()),
                ),
            ])),
        )
        .unwrap();
        let token_hash = store.put(token_entity).unwrap();

        let mut sub = make_sub_data("sub-emit-1", "app/*");
        sub.deliver_token = token_hash;
        engine.register(sub);

        let captured: Arc<std::sync::Mutex<Vec<EmitEvent>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_clone = captured.clone();
        engine.add_emit_hook("test/emit-observer", move |e| {
            captured_clone.lock().unwrap().push(e.clone());
        });

        let changed = Hash::compute("app/data", b"x");
        let event = TreeChangeEvent {
            path: "app/data".to_string(),
            hash: changed,
            previous_hash: None,
            new_hash: Some(changed),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx).unwrap();

        let evts = captured.lock().unwrap();
        assert_eq!(evts.len(), 1, "exactly one emit event expected");
        assert_eq!(evts[0].subscription_id, "sub-emit-1");
        assert_eq!(evts[0].source_change_uri, "app/data");
    }

    #[tokio::test]
    async fn a2_deliver_hook_fires_on_success_and_failure() {
        // GUIDE-INSPECTABILITY v1.2 §2.1 #7: deliver hook fires once per
        // outcome (Ok or Err).
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(Engine::new(store.clone(), index.clone(), "peer1".to_string()));

        let captured: Arc<std::sync::Mutex<Vec<DeliverEvent>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_clone = captured.clone();
        engine.add_deliver_hook("test/deliver-observer", move |e| {
            captured_clone.lock().unwrap().push(e.clone());
        });

        // Helper to build a DeliveryWork for direct deliver_notification testing.
        let notification = Entity::new("test/notif", b"payload".to_vec()).unwrap();
        let notification_hash = notification.content_hash;
        let make_work = || DeliveryWork {
            subscription_id: "sub-deliver".to_string(),
            request: DeliveryRequest {
                request_id: "req-1".to_string(),
                deliver_uri: "user/inbox".to_string(),
                deliver_token: Entity::new("x", b"x".to_vec()).unwrap(),
                params: notification.clone(),
                resource: None,
                included: HashMap::new(),
            },
            chain_id: String::new(),
        };

        // Success case.
        let ok_fn: DeliverFn = Arc::new(|_req| {
            Box::pin(async move { Ok::<(), HandlerError>(()) })
        });
        *engine.deliver.write().unwrap() = Some(ok_fn);
        engine.deliver_notification(make_work()).await;

        // Failure case.
        let err_fn: DeliverFn = Arc::new(|_req| {
            Box::pin(async move {
                Err::<(), HandlerError>(HandlerError::Internal("connection broken".to_string()))
            })
        });
        *engine.deliver.write().unwrap() = Some(err_fn);
        engine.deliver_notification(make_work()).await;

        let evts = captured.lock().unwrap();
        assert_eq!(evts.len(), 2, "expected one success + one failure event");
        assert_eq!(evts[0].subscription_id, "sub-deliver");
        assert_eq!(evts[0].notification_hash, notification_hash);
        assert_eq!(evts[0].status, entity_handler::STATUS_OK);
        assert!(evts[0].error_code.is_none(), "success arm has no error_code");

        assert_eq!(evts[1].status, 0, "failure arm uses status=0 sentinel");
        assert_eq!(
            evts[1].error_code.as_deref(),
            Some("connection_broken"),
            "classified transport reason"
        );
    }

    #[test]
    fn b1_sync_hook_binds_marker_on_max_events_terminate() {
        // EXTENSION-SUBSCRIPTION §4.7: when limit-suppression terminates a
        // subscription, a `lost`-variant chain-error marker MUST bind at
        // `system/runtime/chain-errors/lost/{chain_id}/{subscription_id}/{reason}/{marker_hash}`.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(Engine::new(store.clone(), index.clone(), "peer1".to_string()));

        let token_entity = Entity::new(
            "system/capability/token",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("granter"),
                    entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec()),
                ),
                (
                    entity_ecf::text("grantee"),
                    entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec()),
                ),
            ])),
        )
        .unwrap();
        let token_hash = store.put(token_entity).unwrap();

        // max_events=0 → first delivery attempt triggers Terminate.
        let mut sub = make_sub_data("sub-1", "app/*");
        sub.deliver_token = token_hash;
        sub.limits = Some(SubscriptionLimits {
            max_events: Some(0),
            max_duration_ms: None,
            rate_limit: None,
        });
        engine.register(sub);

        let changed = Hash::compute("app/data", b"x");
        let event = TreeChangeEvent {
            path: "app/data".to_string(),
            hash: changed,
            previous_hash: None,
            new_hash: Some(changed),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        ctx.chain_id = Some("chain-xyz".to_string());
        engine.on_tree_change(&event, &mut ctx).unwrap();

        let prefix = "/peer1/system/runtime/chain-errors/lost/chain-xyz/sub-1/max_events_reached/";
        let bound = index.list(prefix);
        assert!(
            !bound.is_empty(),
            "max_events terminate must bind a §4.7 chain-error marker; \
             expected something under {prefix}, got {:?}",
            bound
        );
    }

    #[test]
    fn b1_sync_hook_binds_marker_on_missing_token() {
        // EXTENSION-SUBSCRIPTION §4.7 capability-rejection: token referenced
        // by the subscription is not in the content store.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(Engine::new(store.clone(), index.clone(), "peer1".to_string()));

        // deliver_token points at a hash that's NEVER put into the store.
        let mut sub = make_sub_data("sub-missing-token", "app/*");
        sub.deliver_token = Hash::compute("phantom", b"unknown");
        engine.register(sub);

        let changed = Hash::compute("app/data", b"x");
        let event = TreeChangeEvent {
            path: "app/data".to_string(),
            hash: changed,
            previous_hash: None,
            new_hash: Some(changed),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        // No chain_id propagated — marker should fall back to subscription_id
        // as the chain segment per chain_error.rs fallback behavior.
        engine.on_tree_change(&event, &mut ctx).unwrap();

        let prefix = "/peer1/system/runtime/chain-errors/lost/sub-missing-token/sub-missing-token/capability_denied/";
        let bound = index.list(prefix);
        assert!(
            !bound.is_empty(),
            "missing-token capability rejection must bind a §4.7 marker; \
             expected something under {prefix}, got {:?}",
            bound
        );
    }

    #[test]
    fn test_build_notification() {
        let hash = Hash::compute("test", b"data");
        let entity = build_notification("sub-1", "created", "app/data", &hash, None).unwrap();
        assert_eq!(entity.entity_type, "system/protocol/inbox/notification");
    }

    #[test]
    fn test_sync_hook_include_payload_attaches_entity() {
        // PROPOSAL-CONVERGENT-MIRRORING §2: when include_payload is set, the
        // changed entity must be attached to DeliveryRequest.included keyed by
        // the new hash. When not set, included must be empty.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(Engine::new(store.clone(), index.clone(), "peer1".to_string()));

        // deliver_token in store (required by hook)
        let token_entity = Entity::new("system/capability/token", entity_ecf::to_ecf(
            &entity_ecf::Value::Map(vec![
                (entity_ecf::text("granter"), entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec())),
                (entity_ecf::text("grantee"), entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec())),
            ])
        )).unwrap();
        let token_hash = store.put(token_entity).unwrap();

        // The actual changed entity that should be bundled.
        let changed_entity = Entity::new("app/data", b"hello".to_vec()).unwrap();
        let changed_hash = store.put(changed_entity.clone()).unwrap();

        // Sub A — opted into include_payload
        let mut sub_a = make_sub_data("sub-A", "app/*");
        sub_a.deliver_token = token_hash;
        sub_a.include_payload = true;
        sub_a.deliver_uri = "user/inbox/A".to_string();
        engine.register(sub_a);

        // Sub B — default (no include_payload)
        let mut sub_b = make_sub_data("sub-B", "app/*");
        sub_b.deliver_token = token_hash;
        sub_b.include_payload = false;
        sub_b.deliver_uri = "user/inbox/B".to_string();
        engine.register(sub_b);

        let event = TreeChangeEvent {
            path: "app/data".to_string(),
            hash: changed_hash,
            previous_hash: None,
            new_hash: Some(changed_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx).unwrap();

        let works = drain_all(&engine);
        assert_eq!(works.len(), 2, "two deliveries expected");
        let mut seen_a_payload = false;
        let mut seen_b_no_payload = false;
        for work in works {
            if work.subscription_id == "sub-A" {
                assert!(
                    work.request.included.contains_key(&changed_hash),
                    "sub-A opted into include_payload — entity must be bundled"
                );
                seen_a_payload = true;
            } else if work.subscription_id == "sub-B" {
                assert!(
                    work.request.included.is_empty(),
                    "sub-B did not opt in — included must be empty"
                );
                seen_b_no_payload = true;
            }
        }
        assert!(seen_a_payload && seen_b_no_payload, "both subs should have fired");
    }

    #[test]
    fn test_sync_hook_include_payload_skips_on_delete() {
        // No new_hash on delete → no entity to bundle, even if opted in.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(Engine::new(store.clone(), index.clone(), "peer1".to_string()));

        let token_entity = Entity::new("system/capability/token", entity_ecf::to_ecf(
            &entity_ecf::Value::Map(vec![
                (entity_ecf::text("granter"), entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec())),
                (entity_ecf::text("grantee"), entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec())),
            ])
        )).unwrap();
        let token_hash = store.put(token_entity).unwrap();

        let mut sub = make_sub_data("sub-del", "app/*");
        sub.deliver_token = token_hash;
        sub.include_payload = true;
        engine.register(sub);

        let prev_hash = Hash::compute("app/data", b"old");
        let event = TreeChangeEvent {
            path: "app/data".to_string(),
            hash: prev_hash, // fallback hash for delete = previous_hash
            previous_hash: Some(prev_hash),
            new_hash: None, // delete
            change_type: ChangeType::Deleted,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx).unwrap();

        let works = drain_all(&engine);
        assert_eq!(works.len(), 1, "delete should still fire notification");
        assert!(works[0].request.included.is_empty(), "no entity on delete");
    }

    #[test]
    fn test_sync_hook_queues_delivery() {
        // Verify that on_tree_change queues a delivery request for a matching
        // subscription.  We read from the delivery channel to confirm.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(Engine::new(store.clone(), index.clone(), "peer1".to_string()));

        // We need a deliver_token entity in the content store
        let token_entity = Entity::new("system/capability/token", entity_ecf::to_ecf(
            &entity_ecf::Value::Map(vec![
                (entity_ecf::text("granter"), entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec())),
                (entity_ecf::text("grantee"), entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec())),
            ])
        )).unwrap();
        let token_hash = store.put(token_entity).unwrap();

        let mut sub = make_sub_data("sub-match", "app/*");
        sub.deliver_token = token_hash;
        engine.register(sub);

        let event = TreeChangeEvent {
            path: "app/data".to_string(),
            hash: Hash::compute("test", b"data"),
            previous_hash: None,
            new_hash: Some(Hash::compute("test", b"data")),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx).unwrap();

        // The delivery work should be queued on this sub's shard.
        let works = drain_all(&engine);
        assert_eq!(works.len(), 1, "should have queued delivery work");
        assert_eq!(works[0].subscription_id, "sub-match");
        assert!(works[0].request.deliver_uri.contains("user/inbox"));
    }

    #[test]
    fn test_sync_hook_cascade_suppression() {
        let engine = make_engine();
        engine.register(make_sub_data("sub-1", "app/*"));

        let event = TreeChangeEvent {
            path: "app/data".to_string(),
            hash: Hash::compute("test", b"data"),
            previous_hash: None,
            new_hash: Some(Hash::compute("test", b"data")),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        ctx.cascade_depth = CASCADE_DEPTH_SUBSCRIPTION_SUPPRESS;
        engine.on_tree_change(&event, &mut ctx).unwrap();

        // Should not have queued anything
        assert!(
            drain_all(&engine).is_empty(),
            "should not queue at cascade depth threshold"
        );
    }

    #[test]
    fn test_sync_hook_self_guard() {
        let engine = make_engine();
        engine.register(make_sub_data("sub-1", "*"));

        // Event on a subscription path itself should be skipped
        let event = TreeChangeEvent {
            path: "/test_peer/system/subscription/sub-1".to_string(),
            hash: Hash::compute("test", b"data"),
            previous_hash: None,
            new_hash: Some(Hash::compute("test", b"data")),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx).unwrap();

        // Should not have queued anything
        assert!(
            drain_all(&engine).is_empty(),
            "should skip self-subscription paths"
        );
    }

    #[test]
    fn test_sync_hook_event_filter() {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(Engine::new(store.clone(), index.clone(), "peer1".to_string()));

        // Register subscription that only wants "created" events
        let token_entity = Entity::new("system/capability/token", entity_ecf::to_ecf(
            &entity_ecf::Value::Map(vec![
                (entity_ecf::text("granter"), entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec())),
                (entity_ecf::text("grantee"), entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec())),
            ])
        )).unwrap();
        let token_hash = store.put(token_entity).unwrap();

        let sub = SubscriptionData {
            subscription_id: "sub-filter".to_string(),
            pattern: "app/*".to_string(),
            events: vec!["created".into()], // only created
            deliver_uri: "user/inbox".to_string(),
            deliver_operation: "receive".to_string(),
            subscriber_identity: Hash::zero(),
            deliver_token: token_hash,
            created_at: 0,
            limits: None,
            include_payload: false,
        };
        engine.register(sub);

        // Send an "updated" event — should not match the filter
        let event = TreeChangeEvent {
            path: "app/data".to_string(),
            hash: Hash::compute("test", b"data"),
            previous_hash: Some(Hash::compute("test", b"old")),
            new_hash: Some(Hash::compute("test", b"data")),
            change_type: ChangeType::Modified,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx).unwrap();

        assert!(
            drain_all(&engine).is_empty(),
            "updated event should not match created-only subscription"
        );
    }

    #[test]
    fn test_shard_for_is_stable() {
        // Same subscription_id MUST always hash to the same shard — that's
        // the within-sub FIFO guarantee (v3.15 §5.2). DefaultHasher is
        // seeded per-process but stable within one run; the contract here
        // is that repeated calls inside one Engine lifetime agree.
        for id in ["sub-A", "sub-B", "sub-C", "sub-1", "sub-2", "longer-id-x"] {
            let a = shard_for(id);
            let b = shard_for(id);
            assert_eq!(a, b, "shard_for({id}) must be stable");
            assert!(a < DELIVERY_SHARD_COUNT);
        }
    }

    #[test]
    fn test_delivery_sharding_distributes_across_workers() {
        // EXTENSION-SUBSCRIPTION v3.15 §5.2 — within-subscription ordering
        // MUST be preserved (FIFO); cross-subscription ordering is impl-
        // defined and we shard across DELIVERY_SHARD_COUNT workers. This
        // test verifies the distribution: a batch of subscription_ids with
        // distinct hashes lands on multiple shards (not all in shard 0).
        //
        // The probe doesn't run a real worker — it queues fake DeliveryWork
        // directly via the shard router and asserts at least two shards
        // received work. That refutes the "single-loop bottleneck" F1
        // shape: the channel is no longer a single queue.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Engine::new(store, index, "peer1".to_string());

        // Generate enough subscription_ids that at least two shards are hit
        // with overwhelming probability (uniform DefaultHasher over 4
        // shards — 32 ids gives P(all in one shard) ≈ 4 * (1/4)^32 ≈ 0).
        let ids: Vec<String> = (0..32).map(|i| format!("probe-sub-{i:03}")).collect();
        let mut per_shard_counts = vec![0usize; DELIVERY_SHARD_COUNT];
        for id in &ids {
            let s = shard_for(id);
            per_shard_counts[s] += 1;
            engine.delivery_txs[s]
                .send(DeliveryWork {
                    subscription_id: id.clone(),
                    request: DeliveryRequest {
                        request_id: format!("req-{id}"),
                        deliver_uri: "user/inbox".to_string(),
                        deliver_token: Entity::new("x", b"x".to_vec()).unwrap(),
                        params: Entity::new("y", b"y".to_vec()).unwrap(),
                        resource: None,
                        included: HashMap::new(),
                    },
                    chain_id: String::new(),
                })
                .unwrap();
        }
        let used_shards = per_shard_counts.iter().filter(|c| **c > 0).count();
        assert!(
            used_shards >= 2,
            "expected work to distribute across >=2 shards; got per_shard_counts={per_shard_counts:?}"
        );

        // Drain each shard independently and verify within-shard FIFO: ids
        // arrive in the order they were sent to their own shard.
        let mut expected_per_shard: Vec<Vec<String>> = vec![Vec::new(); DELIVERY_SHARD_COUNT];
        for id in &ids {
            expected_per_shard[shard_for(id)].push(id.clone());
        }
        let rxs = engine.delivery_rxs.lock().unwrap().take().unwrap();
        for (shard, mut rx) in rxs.into_iter().enumerate() {
            let mut got = Vec::new();
            while let Ok(w) = rx.try_recv() {
                got.push(w.subscription_id);
            }
            assert_eq!(got, expected_per_shard[shard], "shard {shard} FIFO order");
        }
    }
}
