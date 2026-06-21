//! ContentStore + LocationIndex traits and memory implementation.
//!
//! All entity storage flows through these traits — there is exactly
//! one storage pathway, including bootstrap.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};

use entity_entity::Entity;
use entity_hash::Hash;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Tree change events (§6.9 — event notifications)
// ---------------------------------------------------------------------------

/// Type of change in the location index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
}

// ---------------------------------------------------------------------------
// ClockState — structured clock value (CLOCK v1.3, F6)
// ---------------------------------------------------------------------------

/// Structured clock state matching `system/clock/state` type.
///
/// Written by the clock sync consumer at position 2, read by downstream
/// consumers (history at position 4). Replaces the previous `Option<u64>`
/// counter-only representation.
#[derive(Debug, Clone)]
pub struct ClockState {
    pub mode: String,
    pub timestamp: Option<u64>,
    pub logical: Option<ClockLogical>,
    pub vector: Option<HashMap<String, u64>>,
    pub hlc: Option<ClockHlc>,
}

#[derive(Debug, Clone)]
pub struct ClockLogical {
    pub counter: u64,
}

#[derive(Debug, Clone)]
pub struct ClockHlc {
    pub physical: u64,
    pub logical: u64,
    pub peer: Hash,
}

/// Execution context for tree mutations (SYSTEM-COMPOSITION §1.4).
///
/// Carries both immutable cascade fields and per-write fields set by the
/// emit pathway dispatcher for each consumer. Populated by handlers
/// (e.g., TreeHandler) from HandlerContext at the point of write.
/// Engine-initiated writes may use Default (all None/0).
#[derive(Debug, Clone, Default)]
pub struct ExecutionContext {
    // --- Immutable fields (preserved through entire cascade) ---
    /// Causal correlation — all writes in one chain share this.
    pub chain_id: Option<String>,
    /// Identity that initiated the request chain.
    pub author: Option<Hash>,
    /// Original caller's capability from the EXECUTE envelope.
    /// History records this alongside per-write capability to distinguish
    /// "tree handler wrote under caller's authority" from "history handler
    /// wrote under its own grant" (W6 rule).
    pub caller_capability: Option<Hash>,
    /// Correlation ID from originating EXECUTE.
    pub request_id: Option<String>,

    // --- Managed by emit pathway ---
    /// Current depth in the recursive emit cascade. Incremented per nesting
    /// depth, decremented on return. Thresholds: 8 (subscription suppresses),
    /// 16 (compute freezes), 32 (system refuses write).
    pub cascade_depth: u32,

    // --- Per-write fields (set by dispatcher for each consumer) ---
    /// Authorization that produced THIS specific tree write (per V7 §6.8).
    pub capability: Option<Hash>,
    /// Grant of the handler/consumer producing this write.
    pub handler_grant: Option<Hash>,
    /// Pattern of the handler/consumer producing this write.
    pub handler_pattern: Option<String>,
    /// Operation that produced this write.
    pub operation: Option<String>,

    // --- Extension-contributed ---
    /// Parent chain ID — set when a continuation dispatches a sub-chain (G-7).
    /// Absent for root chains.
    pub parent_chain_id: Option<String>,

    /// Structured clock state (F6, CLOCK v1.3). Mutable in-place — advanced
    /// by clock consumer at position 2, visible to subsequent consumers.
    /// None when clock extension is absent.
    pub clock: Option<ClockState>,
}

/// Backward-compatible alias. New code should use `ExecutionContext`.
pub type EmitContext = ExecutionContext;

/// Event emitted when a location index entry changes.
#[derive(Debug, Clone)]
pub struct TreeChangeEvent {
    pub path: String,
    pub hash: Hash,
    pub previous_hash: Option<Hash>,
    pub new_hash: Option<Hash>,
    pub change_type: ChangeType,
    /// Execution context snapshot from the point of the tree write.
    /// None for bootstrap/engine writes that lack handler context.
    pub context: Option<ExecutionContext>,
}

// ---------------------------------------------------------------------------
// SyncTreeHook — synchronous emit pathway consumer (SYSTEM-COMPOSITION §1.2)
// ---------------------------------------------------------------------------

/// A synchronous consumer of tree change events.
///
/// Hooks fire inline during tree writes, in registration order (Phase 1),
/// before the async broadcast (Phase 2). Hooks may read and write the tree,
/// triggering nested hook invocations on the same call stack.
///
/// When writing to the tree during processing, hooks MUST use
/// `location_index.set_with_context(path, hash, ctx.clone())` to preserve
/// the cascade execution context (chain_id, author, cascade_depth).
/// Using plain `set()` loses the context and breaks cascade tracking.
pub trait SyncTreeHook: Send + Sync {
    /// Process a tree change event synchronously.
    ///
    /// The tree has already been mutated (inner.set completed).
    /// `ctx` is the live execution context — hooks may update extension-
    /// contributed fields (e.g., clock updates `ctx.clock`). The per-write
    /// fields (capability, handler_grant, handler_pattern, operation) are
    /// set by the dispatcher to this hook's values before invocation.
    fn on_tree_change(&self, event: &TreeChangeEvent, ctx: &mut ExecutionContext)
        -> Result<(), CascadeHalt>;

    /// Stable consumer name for cascade-halt reporting (§4.4).
    /// SHOULD be prefixed with the owning extension's handler pattern
    /// (e.g., "revision/auto-version", "history/transition-recorder").
    fn name(&self) -> &str;

    /// Handler pattern for per-write context attribution (SYSTEM-COMPOSITION §1.4).
    /// The dispatcher sets `ctx.handler_pattern` to this value before calling `on_tree_change`.
    fn handler_pattern(&self) -> &str;
}

/// Maximum cascade depth before the system refuses the write (§3.2).
pub const CASCADE_DEPTH_LIMIT: u32 = 32;

/// Error returned by a SyncTreeHook to intentionally halt the cascade
/// (SYSTEM-COMPOSITION §2.7, PROPOSAL-CASCADE-SEMANTICS §4.2).
///
/// Non-200 from a Phase 1 consumer means intentional halt. Consumer-internal
/// errors that should not halt MUST NOT be returned as CascadeHalt; handle
/// them inside the consumer.
#[derive(Debug, Clone)]
pub struct CascadeHalt {
    pub consumer_name: String,
    pub error_code: u32,
    pub error_message: String,
    /// True = internal failure (unexpected error), false = intentional halt
    /// (consumer chose to stop the cascade). Used for routing into
    /// `consumers_halted` vs `consumers_errored` in `CascadeResult`.
    pub is_error: bool,
}

/// Result of a tree write's Phase 1 emit cascade
/// (PROPOSAL-CASCADE-SEMANTICS §4.4 `system/tree/partial-result`).
///
/// Returned by `set_with_context` and similar methods on `LocationIndex`.
/// When `is_complete()` is false, the TreeHandler translates this into
/// a 207 Multi-Status response.
#[derive(Debug, Clone)]
pub struct CascadeResult {
    /// Whether the binding update committed. False only for pre-write
    /// rejections (cascade-depth exceeded, invalid path).
    pub binding_committed: bool,
    /// Names of consumers that completed successfully, in execution order.
    pub consumers_completed: Vec<String>,
    /// Consumer(s) that returned non-200 with intentional halt (`is_error: false`).
    pub consumers_halted: Vec<CascadeHalt>,
    /// Consumer(s) that returned non-200 due to internal failure (`is_error: true`).
    pub consumers_errored: Vec<CascadeHalt>,
    /// Names of consumers that were skipped due to the halt.
    pub consumers_skipped: Vec<String>,
    /// Current cascade depth at the time of the write.
    pub cascade_depth: u32,
}

impl CascadeResult {
    /// True when no consumer halted or errored — the cascade completed fully.
    pub fn is_complete(&self) -> bool {
        self.consumers_halted.is_empty() && self.consumers_errored.is_empty() && self.binding_committed
    }

    /// Convenience: a fully-successful cascade with no consumers (non-notifying impls).
    pub fn empty_success() -> Self {
        Self {
            binding_committed: true,
            consumers_completed: Vec::new(),
            consumers_halted: Vec::new(),
            consumers_errored: Vec::new(),
            consumers_skipped: Vec::new(),
            cascade_depth: 0,
        }
    }

    /// A fully-successful cascade with the given consumer names.
    pub fn success(consumers: Vec<String>, depth: u32) -> Self {
        Self {
            binding_committed: true,
            consumers_completed: consumers,
            consumers_halted: Vec::new(),
            consumers_errored: Vec::new(),
            consumers_skipped: Vec::new(),
            cascade_depth: depth,
        }
    }

    /// A pre-write rejection (binding did NOT commit).
    pub fn rejected(halt: CascadeHalt, depth: u32) -> Self {
        Self {
            binding_committed: false,
            consumers_completed: Vec::new(),
            consumers_halted: vec![halt],
            consumers_errored: Vec::new(),
            consumers_skipped: Vec::new(),
            cascade_depth: depth,
        }
    }
}

// ---------------------------------------------------------------------------
// NotifyingLocationIndex — emit pathway dispatcher (SYSTEM-COMPOSITION §1.3)
// ---------------------------------------------------------------------------

/// Emit pathway dispatcher: synchronous hooks (Phase 1) + async broadcast (Phase 2).
///
/// On every tree mutation:
/// 1. Write to inner index (tree mutation)
/// 2. No-op suppression (skip if hash unchanged)
/// 3. Fire sync hooks in registration order (cascade-recursive)
/// 4. Fire async broadcast (settled state)
///
/// Hooks are registered after construction via `register_hook()` to solve
/// the chicken-and-egg: engines need the LocationIndex Arc, and the
/// dispatcher needs engine Arcs as hooks.
pub struct NotifyingLocationIndex {
    inner: Arc<dyn LocationIndex>,
    sync_hooks: RwLock<Vec<Arc<dyn SyncTreeHook>>>,
    on_change_broadcast: Arc<dyn Fn(TreeChangeEvent) + Send + Sync>,
    cascade_depth: Mutex<u32>,
    /// Per-chain cascade depth accumulator (P1). Tracks the accumulated
    /// cascade depth for each chain_id across peers, preventing a chain
    /// crossing N peers from allowing N×CASCADE_DEPTH_LIMIT total depth.
    chain_cascade_depths: Mutex<HashMap<String, u32>>,
    /// Registry of extension-contributed context fields (F4).
    context_field_registry: RwLock<Vec<ContextFieldRegistration>>,
}

/// Formal registration of a context field contributed by an extension (F4).
///
/// Registered at peer init via `NotifyingLocationIndex::register_context_field()`.
/// Provides visibility into which extensions write which `ExecutionContext` fields.
#[derive(Debug, Clone)]
pub struct ContextFieldRegistration {
    /// The field name on `ExecutionContext` (e.g., "clock").
    pub field_name: String,
    /// Extension name that writes this field (e.g., "clock/advance").
    pub owner: String,
    /// Human-readable description.
    pub description: String,
}

impl NotifyingLocationIndex {
    pub fn new(
        inner: Arc<dyn LocationIndex>,
        on_change_broadcast: Arc<dyn Fn(TreeChangeEvent) + Send + Sync>,
    ) -> Self {
        Self {
            inner,
            sync_hooks: RwLock::new(Vec::new()),
            on_change_broadcast,
            cascade_depth: Mutex::new(0),
            chain_cascade_depths: Mutex::new(HashMap::new()),
            context_field_registry: RwLock::new(Vec::new()),
        }
    }

    /// Register a synchronous hook. Hooks fire in registration order.
    /// Call during peer initialization, after engine construction.
    pub fn register_hook(&self, hook: Arc<dyn SyncTreeHook>) {
        self.sync_hooks.write().unwrap().push(hook);
    }

    /// Register an extension-contributed context field (F4).
    pub fn register_context_field(&self, reg: ContextFieldRegistration) {
        self.context_field_registry.write().unwrap().push(reg);
    }

    /// Return all registered context field descriptions.
    pub fn context_fields(&self) -> Vec<ContextFieldRegistration> {
        self.context_field_registry.read().unwrap().clone()
    }
}

/// RAII guard that decrements cascade_depth on drop, even if a hook panics.
struct CascadeGuard<'a> {
    depth: &'a Mutex<u32>,
}

impl Drop for CascadeGuard<'_> {
    fn drop(&mut self) {
        // Use unwrap_or_else to handle poisoned mutex during panic unwind.
        // If the mutex is poisoned, we still need to decrement to avoid
        // permanently bricking the cascade counter.
        let mut guard = self.depth.lock().unwrap_or_else(|e| e.into_inner());
        *guard -= 1;
    }
}

impl NotifyingLocationIndex {
    /// Shared dispatch logic: fire sync hooks then broadcast.
    /// Called after the tree mutation and no-op check have passed.
    ///
    /// Returns a `CascadeResult` describing which consumers ran, halted, or
    /// were skipped. On halt, subsequent Phase 1 consumers are skipped and the
    /// Phase 2 broadcast does NOT fire (PROPOSAL-CASCADE-SEMANTICS §4.2).
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            path = %path,
            change = ?change_type,
            hooks = tracing::field::Empty,
        ),
    )]
    fn dispatch_event(
        &self,
        path: &str,
        hash: Hash,
        previous_hash: Option<Hash>,
        new_hash: Option<Hash>,
        change_type: ChangeType,
        context: Option<ExecutionContext>,
    ) -> CascadeResult {
        // Increment cascade depth. The guard decrements on drop (panic-safe).
        {
            *self.cascade_depth.lock().unwrap() += 1;
        }
        let _guard = CascadeGuard { depth: &self.cascade_depth };

        let mut ctx = context.unwrap_or_default();
        ctx.cascade_depth = *self.cascade_depth.lock().unwrap();

        // Cross-peer cascade depth tracking (P1): when a chain_id is present,
        // check accumulated depth across peers. This prevents a chain crossing
        // N peers from allowing N×CASCADE_DEPTH_LIMIT total depth.
        if let Some(ref chain_id) = ctx.chain_id {
            let mut chain_depths = self.chain_cascade_depths.lock().unwrap();
            let accumulated = chain_depths.entry(chain_id.clone()).or_insert(0);
            let total = *accumulated + ctx.cascade_depth;
            if total > CASCADE_DEPTH_LIMIT {
                tracing::error!(
                    path = %path,
                    chain_id = %chain_id,
                    local_depth = ctx.cascade_depth,
                    accumulated = *accumulated,
                    total,
                    "cross-peer cascade depth limit exceeded"
                );
                return CascadeResult::rejected(CascadeHalt {
                    consumer_name: "system".to_string(),
                    error_code: 500,
                    error_message: "cross_peer_cascade_depth_exceeded".to_string(),
                    is_error: false,
                }, ctx.cascade_depth);
            }
            *accumulated = total;
        }

        let event = TreeChangeEvent {
            path: path.to_string(),
            hash,
            previous_hash,
            new_hash,
            change_type,
            context: Some(ctx.clone()),
        };

        // Phase 1: synchronous hooks (in registration order).
        // Clone the hook list to avoid holding RwLock during dispatch
        // (hooks may write to tree, triggering nested dispatch calls).
        let hooks: Vec<Arc<dyn SyncTreeHook>> =
            self.sync_hooks.read().unwrap().clone();
        let hook_names: Vec<String> = hooks.iter().map(|h| h.name().to_string()).collect();
        tracing::Span::current().record("hooks", hooks.len());
        let mut completed: Vec<String> = Vec::new();

        for (i, hook) in hooks.iter().enumerate() {
            // Save per-write fields from the original writer, set hook's values
            // (SYSTEM-COMPOSITION §1.4: dispatcher sets per-write fields per consumer).
            let saved_pattern = ctx.handler_pattern.take();
            let saved_operation = ctx.operation.take();
            let saved_capability = ctx.capability.take();
            let saved_grant = ctx.handler_grant.take();

            ctx.handler_pattern = Some(hook.handler_pattern().to_string());
            ctx.operation = Some(hook.name().to_string());

            let hook_span = tracing::trace_span!(
                "sync_hook",
                consumer = %hook.name(),
                pattern = %hook.handler_pattern(),
            );
            let result = hook_span.in_scope(|| hook.on_tree_change(&event, &mut ctx));

            // Restore per-write fields for next hook
            ctx.handler_pattern = saved_pattern;
            ctx.operation = saved_operation;
            ctx.capability = saved_capability;
            ctx.handler_grant = saved_grant;

            match result {
                Ok(()) => {
                    completed.push(hook_names[i].clone());
                }
                Err(halt) => {
                    let skipped: Vec<String> = hook_names[i + 1..].to_vec();
                    tracing::warn!(
                        path = %path,
                        consumer = %halt.consumer_name,
                        error_code = halt.error_code,
                        error = %halt.error_message,
                        "cascade halted by Phase 1 consumer"
                    );
                    // Phase 2 broadcast does NOT fire on halt (§4.2).
                    let (halted, errored) = if halt.is_error {
                        (Vec::new(), vec![halt])
                    } else {
                        (vec![halt], Vec::new())
                    };
                    return CascadeResult {
                        binding_committed: true,
                        consumers_completed: completed,
                        consumers_halted: halted,
                        consumers_errored: errored,
                        consumers_skipped: skipped,
                        cascade_depth: ctx.cascade_depth,
                    };
                }
            }
        }

        // Phase 2: async broadcast with settled context.
        // Rebuild the event with post-hook context so Phase 2 consumers
        // (revision, UI, FFI) see the settled execution state.
        let settled_event = TreeChangeEvent {
            context: Some(ctx.clone()),
            ..event
        };
        (self.on_change_broadcast)(settled_event);

        CascadeResult::success(completed, ctx.cascade_depth)
        // _guard drops here, decrementing cascade_depth
    }

    fn set_impl(&self, path: &str, hash: Hash, context: Option<ExecutionContext>) -> CascadeResult {
        if let Err(e) = entity_entity::EntityUri::validate_absolute_path(path) {
            tracing::error!(
                path = %path,
                error = %e,
                "invalid path — refusing write (§5.4 validate_absolute_path)"
            );
            return CascadeResult::rejected(CascadeHalt {
                consumer_name: "system".to_string(),
                error_code: 400,
                error_message: format!("invalid path: {}", e),
                is_error: false,
            }, 0);
        }

        // Cascade depth check — refuse write at threshold (§4.7 pre-write rejection).
        {
            let depth = self.cascade_depth.lock().unwrap();
            if *depth >= CASCADE_DEPTH_LIMIT {
                tracing::error!(
                    path = %path,
                    depth = *depth,
                    "cascade depth limit reached, refusing write"
                );
                return CascadeResult::rejected(CascadeHalt {
                    consumer_name: "system".to_string(),
                    error_code: 500,
                    error_message: "cascade_depth_exceeded".to_string(),
                    is_error: false,
                }, *depth);
            }
        }

        let previous = self.inner.get(path);
        self.inner.set(path, hash);

        // No-op suppression: same hash → no event, no hooks, no broadcast
        let (change_type, previous_hash) = match previous {
            Some(prev) if prev == hash => return CascadeResult::empty_success(),
            Some(prev) => (ChangeType::Modified, Some(prev)),
            None => (ChangeType::Created, None),
        };

        self.dispatch_event(path, hash, previous_hash, Some(hash), change_type, context)
    }

    fn cas_swap_impl(
        &self,
        path: &str,
        expected: Hash,
        new_hash: Hash,
        context: Option<ExecutionContext>,
    ) -> Result<CascadeResult, CasError> {
        if let Err(e) = entity_entity::EntityUri::validate_absolute_path(path) {
            tracing::error!(
                path = %path,
                error = %e,
                "invalid path — refusing CAS (§5.4 validate_absolute_path)"
            );
            return Err(CasError::Mismatch(expected));
        }

        {
            let depth = self.cascade_depth.lock().unwrap();
            if *depth >= CASCADE_DEPTH_LIMIT {
                tracing::error!(
                    path = %path,
                    depth = *depth,
                    "cascade depth limit reached, refusing CAS"
                );
                return Err(CasError::Mismatch(expected));
            }
        }

        self.inner.compare_and_swap(path, expected, new_hash)?;

        if expected == new_hash {
            return Ok(CascadeResult::empty_success());
        }

        Ok(self.dispatch_event(
            path,
            new_hash,
            Some(expected),
            Some(new_hash),
            ChangeType::Modified,
            context,
        ))
    }

    fn cas_remove_impl(
        &self,
        path: &str,
        expected: Hash,
        context: Option<ExecutionContext>,
    ) -> Result<(Hash, CascadeResult), CasError> {
        if let Err(e) = entity_entity::EntityUri::validate_absolute_path(path) {
            tracing::error!(
                path = %path,
                error = %e,
                "invalid path — refusing CAS remove (§5.4 validate_absolute_path)"
            );
            return Err(CasError::Mismatch(expected));
        }

        {
            let depth = self.cascade_depth.lock().unwrap();
            if *depth >= CASCADE_DEPTH_LIMIT {
                tracing::error!(
                    path = %path,
                    depth = *depth,
                    "cascade depth limit reached, refusing CAS remove"
                );
                return Err(CasError::Mismatch(expected));
            }
        }

        let removed = self.inner.compare_and_remove(path, expected)?;
        let cascade = self.dispatch_event(
            path,
            removed,
            Some(removed),
            None,
            ChangeType::Deleted,
            context,
        );
        Ok((removed, cascade))
    }

    fn cas_create_impl(
        &self,
        path: &str,
        new_hash: Hash,
        context: Option<ExecutionContext>,
    ) -> Result<CascadeResult, CasError> {
        if let Err(e) = entity_entity::EntityUri::validate_absolute_path(path) {
            tracing::error!(
                path = %path,
                error = %e,
                "invalid path — refusing CAS-create (§5.4 validate_absolute_path)"
            );
            return Err(CasError::Mismatch(Hash::zero()));
        }

        {
            let depth = self.cascade_depth.lock().unwrap();
            if *depth >= CASCADE_DEPTH_LIMIT {
                tracing::error!(
                    path = %path,
                    depth = *depth,
                    "cascade depth limit reached, refusing CAS-create"
                );
                return Err(CasError::Mismatch(Hash::zero()));
            }
        }

        self.inner.compare_and_create(path, new_hash)?;

        Ok(self.dispatch_event(
            path,
            new_hash,
            None,
            Some(new_hash),
            ChangeType::Created,
            context,
        ))
    }

    fn remove_impl(&self, path: &str, context: Option<ExecutionContext>) -> (Option<Hash>, CascadeResult) {
        if let Err(e) = entity_entity::EntityUri::validate_absolute_path(path) {
            tracing::error!(
                path = %path,
                error = %e,
                "invalid path — refusing remove (§5.4 validate_absolute_path)"
            );
            return (None, CascadeResult::rejected(CascadeHalt {
                consumer_name: "system".to_string(),
                error_code: 400,
                error_message: format!("invalid path: {}", e),
                is_error: false,
            }, 0));
        }

        {
            let depth = self.cascade_depth.lock().unwrap();
            if *depth >= CASCADE_DEPTH_LIMIT {
                tracing::error!(
                    path = %path,
                    depth = *depth,
                    "cascade depth limit reached, refusing remove"
                );
                return (None, CascadeResult::rejected(CascadeHalt {
                    consumer_name: "system".to_string(),
                    error_code: 500,
                    error_message: "cascade_depth_exceeded".to_string(),
                    is_error: false,
                }, *depth));
            }
        }

        let removed = self.inner.remove(path);
        if let Some(prev) = removed {
            let cascade = self.dispatch_event(path, prev, Some(prev), None, ChangeType::Deleted, context);
            (Some(prev), cascade)
        } else {
            (None, CascadeResult::empty_success())
        }
    }
}

impl LocationIndex for NotifyingLocationIndex {
    fn set(&self, path: &str, hash: Hash) {
        let _ = self.set_impl(path, hash, None);
    }

    fn get(&self, path: &str) -> Option<Hash> {
        self.inner.get(path)
    }

    fn has(&self, path: &str) -> bool {
        self.inner.has(path)
    }

    fn remove(&self, path: &str) -> Option<Hash> {
        self.remove_impl(path, None).0
    }

    fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        self.inner.list(prefix)
    }

    fn len_prefix(&self, prefix: &str) -> usize {
        self.inner.len_prefix(prefix)
    }

    fn set_with_context(&self, path: &str, hash: Hash, ctx: ExecutionContext) -> CascadeResult {
        self.set_impl(path, hash, Some(ctx))
    }

    fn remove_with_context(&self, path: &str, ctx: ExecutionContext) -> (Option<Hash>, CascadeResult) {
        self.remove_impl(path, Some(ctx))
    }

    fn compare_and_swap(
        &self,
        path: &str,
        expected: Hash,
        new_hash: Hash,
    ) -> Result<(), CasError> {
        self.cas_swap_impl(path, expected, new_hash, None).map(|_| ())
    }

    fn compare_and_remove(&self, path: &str, expected: Hash) -> Result<Hash, CasError> {
        self.cas_remove_impl(path, expected, None).map(|(h, _)| h)
    }

    fn compare_and_swap_with_context(
        &self,
        path: &str,
        expected: Hash,
        new_hash: Hash,
        ctx: ExecutionContext,
    ) -> Result<CascadeResult, CasError> {
        self.cas_swap_impl(path, expected, new_hash, Some(ctx))
    }

    fn compare_and_remove_with_context(
        &self,
        path: &str,
        expected: Hash,
        ctx: ExecutionContext,
    ) -> Result<(Hash, CascadeResult), CasError> {
        self.cas_remove_impl(path, expected, Some(ctx))
    }

    fn compare_and_create(&self, path: &str, new_hash: Hash) -> Result<(), CasError> {
        self.cas_create_impl(path, new_hash, None).map(|_| ())
    }

    fn compare_and_create_with_context(
        &self,
        path: &str,
        new_hash: Hash,
        ctx: ExecutionContext,
    ) -> Result<CascadeResult, CasError> {
        self.cas_create_impl(path, new_hash, Some(ctx))
    }
}

// ---------------------------------------------------------------------------
// Content store events — parallel to tree change events (§6.9)
// ---------------------------------------------------------------------------

/// Event emitted when a new entity is stored in the content store.
///
/// Per GUIDE-INSPECTABILITY v1.2 §2.1 #1: `is_new` surfaces the
/// "fires only on genuinely new entity" invariant as a typed field so
/// cross-impl observers can decode uniformly. Always `true` at the fire
/// site today (duplicate puts are short-circuited in
/// `NotifyingContentStore::put`); reserved for future use if the dedup
/// posture changes.
#[derive(Debug, Clone)]
pub struct ContentStoreEvent {
    pub hash: Hash,
    pub entity: Entity,
    pub is_new: bool,
}

/// A synchronous consumer of content store events.
///
/// Hooks fire inline during `put()`, in registration order, before the async
/// broadcast. Parallel to `SyncTreeHook` for the location index pathway.
pub trait SyncContentHook: Send + Sync {
    /// Process a content store event synchronously.
    ///
    /// Called only for genuinely new entities (not duplicate puts).
    fn on_content_stored(&self, event: &ContentStoreEvent) -> Result<(), CascadeHalt>;

    /// Stable consumer name for diagnostics.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// NotifyingContentStore — content store emit pathway
// ---------------------------------------------------------------------------

/// Emit pathway dispatcher for content store: sync hooks + async broadcast.
///
/// On every `put()` that stores a genuinely new entity:
/// 1. Delegate to inner store
/// 2. Fire sync hooks in registration order
/// 3. Fire async broadcast
///
/// Duplicate puts (entity already in store) are no-ops — no hooks or
/// broadcast fire, matching content-addressed idempotency semantics.
pub struct NotifyingContentStore {
    inner: Arc<dyn ContentStore>,
    sync_hooks: RwLock<Vec<Arc<dyn SyncContentHook>>>,
    on_store_broadcast: Arc<dyn Fn(ContentStoreEvent) + Send + Sync>,
}

impl NotifyingContentStore {
    pub fn new(
        inner: Arc<dyn ContentStore>,
        on_store_broadcast: Arc<dyn Fn(ContentStoreEvent) + Send + Sync>,
    ) -> Self {
        Self {
            inner,
            sync_hooks: RwLock::new(Vec::new()),
            on_store_broadcast,
        }
    }

    /// Register a synchronous hook. Hooks fire in registration order.
    /// Call during peer initialization, after engine construction.
    pub fn register_hook(&self, hook: Arc<dyn SyncContentHook>) {
        self.sync_hooks.write().unwrap().push(hook);
    }
}

impl ContentStore for NotifyingContentStore {
    fn put(&self, entity: Entity) -> Result<Hash, StoreError> {
        let hash = entity.content_hash;

        // Check if entity already exists — skip hooks/broadcast AND the
        // backend write for duplicates. The inner store is content-addressed
        // (put is idempotent on the same hash) so returning the existing hash
        // is semantically equivalent; on SQLite-backed inner stores this
        // avoids an INSERT OR REPLACE roundtrip on every dedup. H-G3 Layer 1.
        if self.inner.has(&hash) {
            return Ok(hash);
        }

        // Store the entity in the inner store.
        let result = self.inner.put(entity.clone())?;

        let event = ContentStoreEvent {
            hash,
            entity,
            is_new: true,
        };

        // Phase 1: synchronous hooks in registration order.
        let hooks: Vec<Arc<dyn SyncContentHook>> =
            self.sync_hooks.read().unwrap().clone();
        for hook in &hooks {
            if let Err(halt) = hook.on_content_stored(&event) {
                tracing::warn!(
                    hash = %hash,
                    consumer = %halt.consumer_name,
                    error_code = halt.error_code,
                    error = %halt.error_message,
                    "content store cascade halted by sync hook"
                );
                // Content store hooks halting is logged but the entity is
                // already stored (content-addressed stores are append-only).
                // Return success — the entity IS stored.
                return Ok(result);
            }
        }

        // Phase 2: async broadcast.
        (self.on_store_broadcast)(event);

        Ok(result)
    }

    fn get(&self, hash: &Hash) -> Option<Entity> {
        self.inner.get(hash)
    }

    fn has(&self, hash: &Hash) -> bool {
        self.inner.has(hash)
    }

    fn remove(&self, hash: &Hash) -> bool {
        self.inner.remove(hash)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// A content-addressed entity store.
///
/// Entities are stored by their content hash. Implementations must be
/// safe for concurrent access (interior mutability via locks).
pub trait ContentStore: Send + Sync {
    /// Store an entity, keyed by its content hash. Returns the hash.
    fn put(&self, entity: Entity) -> Result<Hash, StoreError>;

    /// Retrieve an entity by its content hash.
    fn get(&self, hash: &Hash) -> Option<Entity>;

    /// Check whether an entity exists.
    fn has(&self, hash: &Hash) -> bool;

    /// Remove an entity. Returns true if it was present.
    fn remove(&self, hash: &Hash) -> bool;

    /// Return the number of stored entities.
    fn len(&self) -> usize;

    /// Check if the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Failure modes for compare-and-swap operations on a `LocationIndex`.
///
/// Returned when the caller's `expected` hash does not match the path's
/// current binding (ENTITY-CORE-PROTOCOL §3.9 — 409 `hash_mismatch`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasError {
    /// A binding exists at the path but its hash differs from `expected`.
    Mismatch(Hash),
    /// No binding exists at the path.
    NotFound,
}

/// A path → hash index for the entity tree.
///
/// Maps string paths to content hashes. Implementations must be
/// safe for concurrent access.
pub trait LocationIndex: Send + Sync {
    /// Set a path to point to a hash.
    fn set(&self, path: &str, hash: Hash);

    /// Get the hash at a path.
    fn get(&self, path: &str) -> Option<Hash>;

    /// Check whether a path exists.
    fn has(&self, path: &str) -> bool;

    /// Remove a path. Returns the previous hash if it existed.
    fn remove(&self, path: &str) -> Option<Hash>;

    /// List all entries matching a prefix, sorted by path.
    fn list(&self, prefix: &str) -> Vec<LocationEntry>;

    /// Count entries matching `prefix` without materializing them.
    ///
    /// Empty prefix MUST be O(1); non-empty SHOULD be O(log N + matches).
    /// Implementations MUST NOT allocate per-entry intermediate state — the
    /// whole point of this method is to skip `list().len()`'s
    /// Vec<LocationEntry> allocation on render-tick callers like
    /// `PeerContext::path_count`.
    ///
    /// Cross-impl convention: mirrors `LenPrefix(prefix)` in the Go
    /// reference.
    fn len_prefix(&self, prefix: &str) -> usize;

    /// Set a path with execution context for richer event notifications.
    /// Default implementation ignores context and delegates to `set`.
    fn set_with_context(&self, path: &str, hash: Hash, _ctx: EmitContext) -> CascadeResult {
        self.set(path, hash);
        CascadeResult::empty_success()
    }

    /// Remove a path with execution context for richer event notifications.
    /// Default implementation ignores context and delegates to `remove`.
    fn remove_with_context(&self, path: &str, _ctx: EmitContext) -> (Option<Hash>, CascadeResult) {
        let removed = self.remove(path);
        (removed, CascadeResult::empty_success())
    }

    /// Atomically set the binding at `path` to `new_hash`, only if the
    /// current binding equals `expected` (ENTITY-CORE-PROTOCOL §3.9).
    ///
    /// The default implementation is a non-atomic `get`+`set` and is
    /// acceptable only for single-threaded or deprecated backends. Real
    /// backends MUST override this with an atomic implementation.
    fn compare_and_swap(
        &self,
        path: &str,
        expected: Hash,
        new_hash: Hash,
    ) -> Result<(), CasError> {
        match self.get(path) {
            Some(current) if current == expected => {
                self.set(path, new_hash);
                Ok(())
            }
            Some(other) => Err(CasError::Mismatch(other)),
            None => Err(CasError::NotFound),
        }
    }

    /// Atomically remove the binding at `path`, only if the current
    /// binding equals `expected`. Returns the removed hash on success.
    fn compare_and_remove(&self, path: &str, expected: Hash) -> Result<Hash, CasError> {
        match self.get(path) {
            Some(current) if current == expected => {
                Ok(self.remove(path).expect("binding existed under our read"))
            }
            Some(other) => Err(CasError::Mismatch(other)),
            None => Err(CasError::NotFound),
        }
    }

    /// CAS variant of `set_with_context`. Default delegates to
    /// `compare_and_swap` and drops the context.
    fn compare_and_swap_with_context(
        &self,
        path: &str,
        expected: Hash,
        new_hash: Hash,
        _ctx: EmitContext,
    ) -> Result<CascadeResult, CasError> {
        self.compare_and_swap(path, expected, new_hash)?;
        Ok(CascadeResult::empty_success())
    }

    /// CAS variant of `remove_with_context`. Default delegates to
    /// `compare_and_remove` and drops the context.
    fn compare_and_remove_with_context(
        &self,
        path: &str,
        expected: Hash,
        _ctx: EmitContext,
    ) -> Result<(Hash, CascadeResult), CasError> {
        let removed = self.compare_and_remove(path, expected)?;
        Ok((removed, CascadeResult::empty_success()))
    }

    /// Atomically bind `path` to `new_hash`, only if the path is currently
    /// unbound. V7 §3.9 (v7.50) CAS-create: callers signal "expect absent"
    /// with `expected_hash = zero` in `tree:put`. Returns `CasError::Mismatch`
    /// carrying the existing binding when the path is already bound.
    ///
    /// The default impl is a non-atomic `get` + `set`. Concrete backends MUST
    /// override with an atomic implementation for correctness under
    /// concurrency.
    fn compare_and_create(&self, path: &str, new_hash: Hash) -> Result<(), CasError> {
        match self.get(path) {
            Some(current) => Err(CasError::Mismatch(current)),
            None => {
                self.set(path, new_hash);
                Ok(())
            }
        }
    }

    /// Cascade-aware CAS-create variant. Default delegates to
    /// `compare_and_create` and drops the context.
    fn compare_and_create_with_context(
        &self,
        path: &str,
        new_hash: Hash,
        _ctx: EmitContext,
    ) -> Result<CascadeResult, CasError> {
        self.compare_and_create(path, new_hash)?;
        Ok(CascadeResult::empty_success())
    }
}

/// An entry in a location index listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationEntry {
    pub path: String,
    pub hash: Hash,
}

/// In-memory content store backed by a `BTreeMap`.
pub struct MemoryContentStore {
    entities: RwLock<BTreeMap<Hash, Entity>>,
}

impl MemoryContentStore {
    pub fn new() -> Self {
        Self {
            entities: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Default for MemoryContentStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryContentStore {
    /// Return all stored entities as (hash, entity) pairs.
    pub fn entries(&self) -> Vec<(Hash, Entity)> {
        self.entities
            .read()
            .unwrap()
            .iter()
            .map(|(h, e)| (*h, e.clone()))
            .collect()
    }
}

impl ContentStore for MemoryContentStore {
    fn put(&self, entity: Entity) -> Result<Hash, StoreError> {
        let hash = entity.content_hash;
        self.entities.write().unwrap().insert(hash, entity);
        Ok(hash)
    }

    fn get(&self, hash: &Hash) -> Option<Entity> {
        self.entities.read().unwrap().get(hash).cloned()
    }

    fn has(&self, hash: &Hash) -> bool {
        self.entities.read().unwrap().contains_key(hash)
    }

    fn remove(&self, hash: &Hash) -> bool {
        self.entities.write().unwrap().remove(hash).is_some()
    }

    fn len(&self) -> usize {
        self.entities.read().unwrap().len()
    }
}

/// In-memory location index backed by a `BTreeMap`.
pub struct MemoryLocationIndex {
    paths: RwLock<BTreeMap<String, Hash>>,
}

impl MemoryLocationIndex {
    pub fn new() -> Self {
        Self {
            paths: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Default for MemoryLocationIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryLocationIndex {
    /// Return all stored entries as (path, hash) pairs.
    pub fn entries(&self) -> Vec<(String, Hash)> {
        self.paths
            .read()
            .unwrap()
            .iter()
            .map(|(p, h)| (p.clone(), *h))
            .collect()
    }
}

impl LocationIndex for MemoryLocationIndex {
    fn set(&self, path: &str, hash: Hash) {
        self.paths.write().unwrap().insert(path.to_string(), hash);
    }

    fn get(&self, path: &str) -> Option<Hash> {
        self.paths.read().unwrap().get(path).copied()
    }

    fn has(&self, path: &str) -> bool {
        self.paths.read().unwrap().contains_key(path)
    }

    fn remove(&self, path: &str) -> Option<Hash> {
        self.paths.write().unwrap().remove(path)
    }

    fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        let paths = self.paths.read().unwrap();
        // BTreeMap iteration is already sorted by key
        paths
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| LocationEntry {
                path: k.clone(),
                hash: *v,
            })
            .collect()
    }

    fn len_prefix(&self, prefix: &str) -> usize {
        let paths = self.paths.read().unwrap();
        if prefix.is_empty() {
            return paths.len();
        }
        paths
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .count()
    }

    fn compare_and_swap(
        &self,
        path: &str,
        expected: Hash,
        new_hash: Hash,
    ) -> Result<(), CasError> {
        let mut paths = self.paths.write().unwrap();
        match paths.get(path) {
            Some(current) if *current == expected => {
                paths.insert(path.to_string(), new_hash);
                Ok(())
            }
            Some(other) => Err(CasError::Mismatch(*other)),
            None => Err(CasError::NotFound),
        }
    }

    fn compare_and_remove(&self, path: &str, expected: Hash) -> Result<Hash, CasError> {
        let mut paths = self.paths.write().unwrap();
        match paths.get(path) {
            Some(current) if *current == expected => Ok(paths.remove(path).unwrap()),
            Some(other) => Err(CasError::Mismatch(*other)),
            None => Err(CasError::NotFound),
        }
    }

    fn compare_and_create(&self, path: &str, new_hash: Hash) -> Result<(), CasError> {
        let mut paths = self.paths.write().unwrap();
        match paths.get(path) {
            Some(current) => Err(CasError::Mismatch(*current)),
            None => {
                paths.insert(path.to_string(), new_hash);
                Ok(())
            }
        }
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "persist")]
pub mod persist;

#[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
pub mod opfs;

#[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
pub mod idb;

#[cfg(test)]
pub(crate) mod test_suite;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ContentStore tests (via shared suite) ---

    #[test]
    fn test_content_store_put_get() { test_suite::test_content_store_put_get(&MemoryContentStore::new()); }
    #[test]
    fn test_content_store_has() { test_suite::test_content_store_has(&MemoryContentStore::new()); }
    #[test]
    fn test_content_store_remove() { test_suite::test_content_store_remove(&MemoryContentStore::new()); }
    #[test]
    fn test_content_store_len() { test_suite::test_content_store_len(&MemoryContentStore::new()); }
    #[test]
    fn test_content_store_get_missing() { test_suite::test_content_store_get_missing(&MemoryContentStore::new()); }
    #[test]
    fn test_content_store_put_overwrite() { test_suite::test_content_store_put_overwrite(&MemoryContentStore::new()); }
    #[test]
    fn test_content_store_multiple_entities() { test_suite::test_content_store_multiple_entities(&MemoryContentStore::new()); }

    // --- LocationIndex tests (via shared suite) ---

    #[test]
    fn test_location_index_set_get() { test_suite::test_location_index_set_get(&MemoryLocationIndex::new()); }
    #[test]
    fn test_location_index_has() { test_suite::test_location_index_has(&MemoryLocationIndex::new()); }
    #[test]
    fn test_location_index_remove() { test_suite::test_location_index_remove(&MemoryLocationIndex::new()); }
    #[test]
    fn test_location_index_get_missing() { test_suite::test_location_index_get_missing(&MemoryLocationIndex::new()); }
    #[test]
    fn test_location_index_overwrite() { test_suite::test_location_index_overwrite(&MemoryLocationIndex::new()); }
    #[test]
    fn test_location_index_list_prefix() { test_suite::test_location_index_list_prefix(&MemoryLocationIndex::new()); }
    #[test]
    fn test_location_index_list_all() { test_suite::test_location_index_list_all(&MemoryLocationIndex::new()); }

    #[test]
    fn test_location_index_list_empty() {
        let index = MemoryLocationIndex::new();
        let entries = index.list("system/");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_location_index_list_no_match() {
        let index = MemoryLocationIndex::new();
        let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("x")));
        index.set("other/path", hash);
        let entries = index.list("system/");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_location_index_len_prefix() {
        test_suite::test_location_index_len_prefix(&MemoryLocationIndex::new());
    }

    // --- CAS tests (memory) ---

    #[test]
    fn test_cas_swap_match_succeeds() { test_suite::test_cas_swap_match_succeeds(&MemoryLocationIndex::new()); }
    #[test]
    fn test_cas_swap_mismatch_returns_actual() { test_suite::test_cas_swap_mismatch_returns_actual(&MemoryLocationIndex::new()); }
    #[test]
    fn test_cas_swap_missing_returns_not_found() { test_suite::test_cas_swap_missing_returns_not_found(&MemoryLocationIndex::new()); }
    #[test]
    fn test_cas_remove_match_succeeds() { test_suite::test_cas_remove_match_succeeds(&MemoryLocationIndex::new()); }
    #[test]
    fn test_cas_remove_mismatch_returns_actual() { test_suite::test_cas_remove_mismatch_returns_actual(&MemoryLocationIndex::new()); }
    #[test]
    fn test_cas_remove_missing_returns_not_found() { test_suite::test_cas_remove_missing_returns_not_found(&MemoryLocationIndex::new()); }

    // --- NotifyingLocationIndex tests ---

    use std::sync::Mutex;

    /// 46-char Base58 fixture. Real peer IDs are `Base58(key_type || hash_type
    /// || SHA-256(pubkey))` = 46 chars for Ed25519 + SHA-256 (§1.5). The
    /// validator in NotifyingLocationIndex (§5.4) only checks length + alphabet,
    /// so a constant suffices here without pulling in entity-crypto.
    const TEST_PEER: &str = "testPeerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn notifying_index() -> (NotifyingLocationIndex, Arc<Mutex<Vec<TreeChangeEvent>>>) {
        let inner = Arc::new(MemoryLocationIndex::new());
        let events: Arc<Mutex<Vec<TreeChangeEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();
        let on_change = Arc::new(move |evt: TreeChangeEvent| {
            events_clone.lock().unwrap().push(evt);
        });
        (NotifyingLocationIndex::new(inner, on_change), events)
    }

    #[test]
    fn test_notifying_set_created() {
        let (index, events) = notifying_index();
        let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("a")));
        let path = format!("/{}/path/a", TEST_PEER);
        index.set(&path, hash);

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].change_type, ChangeType::Created);
        assert_eq!(evts[0].path, path);
        assert!(evts[0].previous_hash.is_none());
        assert_eq!(evts[0].new_hash, Some(hash));
    }

    #[test]
    fn test_notifying_set_modified() {
        let (index, events) = notifying_index();
        let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("1")));
        let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("2")));
        let path = format!("/{}/path/a", TEST_PEER);
        index.set(&path, h1);
        index.set(&path, h2);

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 2);
        assert_eq!(evts[1].change_type, ChangeType::Modified);
        assert_eq!(evts[1].previous_hash, Some(h1));
        assert_eq!(evts[1].new_hash, Some(h2));
    }

    #[test]
    fn test_notifying_set_same_no_event() {
        let (index, events) = notifying_index();
        let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("x")));
        let path = format!("/{}/p", TEST_PEER);
        index.set(&path, hash);
        index.set(&path, hash); // same hash — should not fire

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1); // only the initial Created
    }

    #[test]
    fn test_notifying_remove_fires_deleted() {
        let (index, events) = notifying_index();
        let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("x")));
        let path = format!("/{}/p", TEST_PEER);
        index.set(&path, hash);
        let removed = index.remove(&path);
        assert_eq!(removed, Some(hash));

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 2);
        assert_eq!(evts[1].change_type, ChangeType::Deleted);
        assert_eq!(evts[1].previous_hash, Some(hash));
        assert!(evts[1].new_hash.is_none());
    }

    #[test]
    fn test_notifying_remove_missing_no_event() {
        let (index, events) = notifying_index();
        let path = format!("/{}/nonexistent", TEST_PEER);
        let removed = index.remove(&path);
        assert!(removed.is_none());
        assert!(events.lock().unwrap().is_empty());
    }

    #[test]
    fn test_notifying_delegates_reads() {
        let (index, _events) = notifying_index();
        let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("r")));
        let path = format!("/{}/a/b", TEST_PEER);
        index.set(&path, hash);
        assert_eq!(index.get(&path), Some(hash));
        assert!(index.has(&path));
        assert!(!index.has(&format!("/{}/x/y", TEST_PEER)));
        let entries = index.list(&format!("/{}/a/", TEST_PEER));
        assert_eq!(entries.len(), 1);
    }

    /// A bare (non-peer-qualified) write must be refused by the validator
    /// guard per ENTITY-CORE-PROTOCOL-V7 §5.4.
    #[test]
    fn test_notifying_refuses_unqualified_path() {
        let (index, events) = notifying_index();
        let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("r")));
        index.set("bare/path", hash);
        assert!(index.get("bare/path").is_none(), "write must be refused");
        assert!(events.lock().unwrap().is_empty());
    }

    // --- Cascade halt tests (PROPOSAL-CASCADE-SEMANTICS §4.2) ---

    struct HaltingHook {
        hook_name: String,
    }

    impl SyncTreeHook for HaltingHook {
        fn on_tree_change(&self, _event: &TreeChangeEvent, _ctx: &mut ExecutionContext)
            -> Result<(), CascadeHalt>
        {
            Err(CascadeHalt {
                consumer_name: self.hook_name.clone(),
                error_code: 500,
                error_message: "test halt".to_string(),
                is_error: false,
            })
        }
        fn name(&self) -> &str { &self.hook_name }
        fn handler_pattern(&self) -> &str { "test" }
    }

    struct PassingHook {
        hook_name: String,
    }

    impl SyncTreeHook for PassingHook {
        fn on_tree_change(&self, _event: &TreeChangeEvent, _ctx: &mut ExecutionContext)
            -> Result<(), CascadeHalt>
        {
            Ok(())
        }
        fn name(&self) -> &str { &self.hook_name }
        fn handler_pattern(&self) -> &str { "test" }
    }

    #[test]
    fn test_cascade_halt_short_circuits_subsequent_hooks() {
        let (index, events) = notifying_index();
        index.register_hook(Arc::new(PassingHook { hook_name: "hook-a".into() }));
        index.register_hook(Arc::new(HaltingHook { hook_name: "hook-b".into() }));
        index.register_hook(Arc::new(PassingHook { hook_name: "hook-c".into() }));

        let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v")));
        let path = format!("/{}/test/path", TEST_PEER);
        let cr = index.set_with_context(&path, hash, ExecutionContext::default());

        assert!(cr.binding_committed);
        assert!(!cr.is_complete());
        assert_eq!(cr.consumers_completed, vec!["hook-a"]);
        assert_eq!(cr.consumers_halted.len(), 1);
        assert_eq!(cr.consumers_halted[0].consumer_name, "hook-b");
        assert_eq!(cr.consumers_skipped, vec!["hook-c"]);

        // Phase 2 broadcast should NOT fire on halt
        assert!(events.lock().unwrap().is_empty());
    }

    #[test]
    fn test_cascade_success_fires_broadcast() {
        let (index, events) = notifying_index();
        index.register_hook(Arc::new(PassingHook { hook_name: "hook-a".into() }));
        index.register_hook(Arc::new(PassingHook { hook_name: "hook-b".into() }));

        let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v")));
        let path = format!("/{}/test/path", TEST_PEER);
        let cr = index.set_with_context(&path, hash, ExecutionContext::default());

        assert!(cr.is_complete());
        assert_eq!(cr.consumers_completed, vec!["hook-a", "hook-b"]);
        assert!(cr.consumers_halted.is_empty());
        assert!(cr.consumers_skipped.is_empty());

        // Phase 2 broadcast fires on success
        assert_eq!(events.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_cascade_depth_exceeded_rejects_write() {
        let (index, _events) = notifying_index();
        let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v")));
        let path = format!("/{}/test/path", TEST_PEER);

        // Simulate depth at limit
        *index.cascade_depth.lock().unwrap() = CASCADE_DEPTH_LIMIT;
        let cr = index.set_with_context(&path, hash, ExecutionContext::default());

        assert!(!cr.binding_committed);
        assert!(!cr.is_complete());
        assert_eq!(cr.consumers_halted[0].error_message, "cascade_depth_exceeded");
        assert!(index.get(&path).is_none(), "write should not have committed");

        // Reset depth for cleanup
        *index.cascade_depth.lock().unwrap() = 0;
    }

    // --- NotifyingContentStore tests ---

    fn notifying_store() -> (NotifyingContentStore, Arc<Mutex<Vec<ContentStoreEvent>>>) {
        let inner = Arc::new(MemoryContentStore::new());
        let events: Arc<Mutex<Vec<ContentStoreEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();
        let on_store = Arc::new(move |evt: ContentStoreEvent| {
            events_clone.lock().unwrap().push(evt);
        });
        (NotifyingContentStore::new(inner, on_store), events)
    }

    fn test_entity(label: &str) -> Entity {
        Entity::new("test/type", entity_ecf::to_ecf(&entity_ecf::text(label))).unwrap()
    }

    #[test]
    fn test_notifying_content_store_put_fires_event() {
        let (store, events) = notifying_store();
        let entity = test_entity("hello");
        let hash = store.put(entity.clone()).unwrap();

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].hash, hash);
        assert_eq!(evts[0].entity.entity_type, "test/type");
    }

    #[test]
    fn test_notifying_content_store_duplicate_put_no_event() {
        let (store, events) = notifying_store();
        let entity = test_entity("dup");
        store.put(entity.clone()).unwrap();
        store.put(entity.clone()).unwrap(); // duplicate — should not fire

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 1, "duplicate put should not fire a second event");
    }

    #[test]
    fn test_notifying_content_store_different_entities_fire_events() {
        let (store, events) = notifying_store();
        store.put(test_entity("a")).unwrap();
        store.put(test_entity("b")).unwrap();
        store.put(test_entity("c")).unwrap();

        let evts = events.lock().unwrap();
        assert_eq!(evts.len(), 3);
    }

    #[test]
    fn test_notifying_content_store_delegates_get() {
        let (store, _events) = notifying_store();
        let entity = test_entity("get-me");
        let hash = store.put(entity.clone()).unwrap();

        let retrieved = store.get(&hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().entity_type, "test/type");
    }

    #[test]
    fn test_notifying_content_store_delegates_has() {
        let (store, _events) = notifying_store();
        let entity = test_entity("has-me");
        let hash = store.put(entity).unwrap();

        assert!(store.has(&hash));
        assert!(!store.has(&Hash::compute("other", &[0u8])));
    }

    #[test]
    fn test_notifying_content_store_delegates_remove() {
        let (store, _events) = notifying_store();
        let entity = test_entity("remove-me");
        let hash = store.put(entity).unwrap();

        assert!(store.remove(&hash));
        assert!(!store.has(&hash));
        assert!(!store.remove(&hash)); // already removed
    }

    #[test]
    fn test_notifying_content_store_delegates_len() {
        let (store, _events) = notifying_store();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());

        store.put(test_entity("a")).unwrap();
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());

        store.put(test_entity("b")).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_notifying_content_store_sync_hook_fires() {
        struct CountingHook {
            count: Mutex<u32>,
        }
        impl SyncContentHook for CountingHook {
            fn on_content_stored(&self, _event: &ContentStoreEvent) -> Result<(), CascadeHalt> {
                *self.count.lock().unwrap() += 1;
                Ok(())
            }
            fn name(&self) -> &str { "counting-hook" }
        }

        let (store, _events) = notifying_store();
        let hook = Arc::new(CountingHook { count: Mutex::new(0) });
        store.register_hook(hook.clone());

        store.put(test_entity("x")).unwrap();
        store.put(test_entity("y")).unwrap();
        store.put(test_entity("x")).unwrap(); // duplicate — hook should not fire

        assert_eq!(*hook.count.lock().unwrap(), 2);
    }

    #[test]
    fn test_notifying_content_store_hook_halt_suppresses_broadcast() {
        struct HaltHook;
        impl SyncContentHook for HaltHook {
            fn on_content_stored(&self, _event: &ContentStoreEvent) -> Result<(), CascadeHalt> {
                Err(CascadeHalt {
                    consumer_name: "halt-hook".to_string(),
                    error_code: 500,
                    error_message: "test halt".to_string(),
                    is_error: false,
                })
            }
            fn name(&self) -> &str { "halt-hook" }
        }

        let (store, events) = notifying_store();
        store.register_hook(Arc::new(HaltHook));

        // Entity should still be stored (content store is append-only)
        let hash = store.put(test_entity("halted")).unwrap();
        assert!(store.has(&hash));

        // Broadcast should NOT fire due to hook halt
        assert!(events.lock().unwrap().is_empty());
    }
}
