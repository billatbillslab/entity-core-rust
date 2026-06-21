//! Handler trait, registry, context, and dispatch.
//!
//! Per spec §6.5–6.8: handlers are async functions that process operations.
//! `HandlerContext` currently carries 16 fields: the spec-defined inputs (§6.8)
//! plus a small set of dispatch/capability/bounds support fields. Each field is
//! documented at the struct definition with its rationale; the count is a
//! reviewed ceiling rather than a hard limit. See CLAUDE.md anti-pattern #1.
//! Dispatch resolves handlers by longest prefix match.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use entity_capability::CapabilityToken;
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::TYPE_ERROR;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Status codes (§3.3)
// ---------------------------------------------------------------------------

pub const STATUS_OK: u32 = 200;
/// Accepted — completion is asynchronous, observed elsewhere (inbox delivery;
/// also the durability "committed, completes asynchronously" verdict when
/// EXTENSION-DURABILITY is installed). EXTENSION-INBOX §7.1 owns the inbox-ack
/// semantics independently of durability; EXTENSION-DURABILITY §5 reuses the
/// same 202 meaning. V7 v7.46 does not list 202 in its core status table.
pub const STATUS_ACCEPTED: u32 = 202;
pub const STATUS_MULTI_STATUS: u32 = 207;
pub const STATUS_REDIRECT: u32 = 303;
pub const STATUS_BAD_REQUEST: u32 = 400;
pub const STATUS_AUTH_FAILED: u32 = 401;
pub const STATUS_FORBIDDEN: u32 = 403;
pub const STATUS_NOT_FOUND: u32 = 404;
pub const STATUS_CONFLICT: u32 = 409;
/// Precondition failed — a required durability precondition could not be met;
/// the operation was **not performed** (refused at acceptance). Safe to retry
/// elsewhere, no double-execution. Only used within EXTENSION-DURABILITY §5/§8;
/// V7 v7.46 does not reserve 412 at the core level.
pub const STATUS_PRECONDITION_FAILED: u32 = 412;
pub const STATUS_RATE_LIMITED: u32 = 429;
pub const STATUS_INTERNAL_ERROR: u32 = 500;
pub const STATUS_NOT_SUPPORTED: u32 = 501;
pub const STATUS_BAD_GATEWAY: u32 = 502;
pub const STATUS_UNAVAILABLE: u32 = 503;

// ---------------------------------------------------------------------------
// ExecuteFn — handler-to-handler dispatch (§6.8)
// ---------------------------------------------------------------------------

/// Options for handler-to-handler dispatch via ExecuteFn.
#[derive(Debug, Clone, Default)]
pub struct ExecuteOptions {
    /// Override resource target for the child dispatch.
    pub resource: Option<entity_capability::ResourceTarget>,
    /// Override capability entity for Level 1 check.
    pub capability: Option<Entity>,
    /// Delivery specification for continuation routing.
    pub deliver_to: Option<DeliverySpec>,
    /// Override request_id for the child context (default: "internal").
    pub request_id: Option<String>,
    /// Override bounds for the child dispatch. If absent, parent bounds are
    /// inherited and TTL is decremented (§5.9 bounds propagation).
    pub bounds: Option<Bounds>,
    /// Explicit authority-chain entities to carry in the outbound EXECUTE's
    /// envelope `included` set (the §6.13(b) seam). Use this when the chain
    /// rides **in-band** (e.g. GUIDE-CONFORMANCE §7a.2a, where the granter
    /// identity + capability signature arrive nested in params) rather than
    /// in the local store — `collect_chain_bundle` walks the store and so
    /// cannot find an in-band chain. This is the Rust analog of Go's
    /// `WithIncludedChain`. Default empty: ordinary dispatch is unchanged.
    pub included: Vec<Entity>,
}

/// Delivery specification (target URI + operation for forwarding results).
#[derive(Debug, Clone)]
pub struct DeliverySpec {
    pub uri: String,
    pub operation: String,
}

/// Execution bounds for an operation (§3.11, §5.9).
///
/// Bounds travel with operations through the system. TTL decrements at each
/// dispatch hop. chain_id is inherited (correlates writes across a handler chain).
/// visited is appended on remote dispatch (cycle detection).
#[derive(Debug, Clone, Default)]
pub struct Bounds {
    pub ttl: Option<u64>,
    pub budget: Option<u64>,
    pub cascade_depth: Option<u64>,
    pub chain_id: Option<String>,
    pub parent_chain_id: Option<String>,
    pub visited: Vec<String>,
}

impl Bounds {
    /// Decrement TTL by 1. Returns Err if TTL was already 0 (ttl_exhausted).
    /// All other fields are inherited unchanged.
    pub fn decrement(&self) -> Result<Self, HandlerError> {
        let mut child = self.clone();
        if let Some(ttl) = child.ttl {
            if ttl == 0 {
                return Err(HandlerError::Internal("ttl_exhausted".to_string()));
            }
            child.ttl = Some(ttl - 1);
        }
        Ok(child)
    }
}

/// Handler-to-handler dispatch function.
///
/// Signature: (handler_path, operation, params, options) -> result.
/// On native, futures are Send (tokio multi-threaded). On WASM, !Send (single-threaded).
#[cfg(not(target_arch = "wasm32"))]
pub type ExecuteFn = Arc<
    dyn Fn(
            String,
            String,
            Entity,
            ExecuteOptions,
        ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>> + Send>>
        + Send
        + Sync,
>;

#[cfg(target_arch = "wasm32")]
pub type ExecuteFn = Arc<
    dyn Fn(
            String,
            String,
            Entity,
            ExecuteOptions,
        ) -> Pin<Box<dyn Future<Output = Result<HandlerResult, HandlerError>>>>
>;

// ---------------------------------------------------------------------------
// Handler trait
// ---------------------------------------------------------------------------

/// A handler processes operations for a given pattern.
///
/// Handlers are async and receive a context with all spec-defined information.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait Handler: Send + Sync {
    /// Handle an operation, returning a result entity or error.
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError>;

    /// The handler's pattern (e.g., "system/tree").
    fn pattern(&self) -> &str;

    /// The handler's name.
    fn name(&self) -> &str;

    /// Operations this handler supports.
    fn operations(&self) -> &[&str];

    /// Internal scope declaring what this handler needs for its own operations (§6.9).
    ///
    /// Returns `None` for the default wildcard scope (all handlers, all resources,
    /// all operations). Handlers that need narrower self-authorization override this.
    /// Used by the bootstrap sequence to create the handler's capability grant.
    fn internal_scope(&self) -> Option<Vec<entity_capability::GrantEntry>> {
        None
    }
}

// ---------------------------------------------------------------------------
// Dispatcher trait (SDK-EXTENSION-OPERATIONS §11 Amendment A)
// ---------------------------------------------------------------------------

/// The dispatch contract both `PeerContext` (outer-caller / cross-peer) and
/// handler-internal dispatch sites satisfy.
///
/// Per SDK-EXTENSION-OPERATIONS §11 Amendment A: `content::ensure_closure`
/// (and any future SDK-level sequencer over `system/content:get`) takes a
/// `&dyn Dispatcher` so the §7.2 closure-fetch algorithm lives once. Both
/// shapes ride the same cap-checked dispatch chain — handler-internal calls
/// go through the handler's `internal_scope` grant; outer calls go through
/// the caller's grant. No privilege amplification, per V7 §6.8 v7.49.
///
/// Built-in dispatcher impls in this crate:
///
/// - [`HandlerContextDispatcher`] — wraps a [`HandlerContext`] for
///   handler-internal sub-dispatch. URIs target the local peer.
/// - [`PeerAimedDispatcher`] — wraps a [`HandlerContext`] for
///   handler-to-cross-peer dispatch. Every URI is rewritten to
///   `entity://{source_peer_id}/{handler}` before forwarding.
///
/// Outer callers (`bindings/sdk::PeerContext`) implement `Dispatcher`
/// directly. See `bindings/sdk` for that impl.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait Dispatcher: Send + Sync {
    /// Dispatch an EXECUTE against `handler` / `operation` with `params`.
    /// `opts` carries the resource (path-as-resource per V7 §3.2), an
    /// optional capability override, delivery spec, request_id, and bounds.
    async fn execute(
        &self,
        handler: &str,
        operation: &str,
        params: Entity,
        opts: ExecuteOptions,
    ) -> Result<HandlerResult, HandlerError>;
}

/// WASM variant — no `Send + Sync` bounds since the single-threaded
/// runtime doesn't require them and `ExecuteFn` itself is `!Send`.
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait Dispatcher {
    async fn execute(
        &self,
        handler: &str,
        operation: &str,
        params: Entity,
        opts: ExecuteOptions,
    ) -> Result<HandlerResult, HandlerError>;
}

/// Adapter from [`HandlerContext`] to [`Dispatcher`] for handler-internal
/// sub-dispatch. The handler's `internal_scope` grant gates each sub-dispatch
/// per V7 §6.8 v7.49 (propagated caller capability is NOT a dispatch gate).
///
/// Constructed by [`HandlerContext::dispatcher`]; callers typically take
/// `&dyn Dispatcher` so impls can be swapped for testing.
pub struct HandlerContextDispatcher<'a> {
    execute_fn: &'a ExecuteFn,
}

impl<'a> HandlerContextDispatcher<'a> {
    /// Borrow the dispatch closure off a `HandlerContext`. Returns `None`
    /// when the context was assembled without an `execute_fn` (e.g., a
    /// unit-test stub for a non-dispatching handler).
    pub fn new(ctx: &'a HandlerContext) -> Option<Self> {
        ctx.execute_fn.as_ref().map(|f| Self { execute_fn: f })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<'a> Dispatcher for HandlerContextDispatcher<'a> {
    async fn execute(
        &self,
        handler: &str,
        operation: &str,
        params: Entity,
        opts: ExecuteOptions,
    ) -> Result<HandlerResult, HandlerError> {
        (self.execute_fn)(handler.to_string(), operation.to_string(), params, opts).await
    }
}

/// Adapter from [`HandlerContext`] to [`Dispatcher`] for handler-driven
/// cross-peer dispatch. Every EXECUTE the wrapped handler issues is
/// rewritten to target `entity://{source_peer_id}/{handler}` before
/// forwarding through the underlying `execute_fn`.
///
/// Returned by `content::at_peer` per SDK-EXTENSION-OPERATIONS §11.
/// The namespace argument to [`Dispatcher::execute`] callers (e.g.,
/// `content::ensure_closure`) stays a pure cap-scope concept; peer
/// authority is this Dispatcher's concern.
pub struct PeerAimedDispatcher<'a> {
    execute_fn: &'a ExecuteFn,
    source_peer_id: String,
}

impl<'a> PeerAimedDispatcher<'a> {
    /// Build a peer-aimed dispatcher from a `HandlerContext` + target peer.
    /// Returns `None` when the context lacks an `execute_fn`.
    pub fn new(ctx: &'a HandlerContext, source_peer_id: impl Into<String>) -> Option<Self> {
        ctx.execute_fn.as_ref().map(|f| Self {
            execute_fn: f,
            source_peer_id: source_peer_id.into(),
        })
    }

    fn qualify(&self, handler: &str) -> String {
        // Don't re-wrap a URI that already carries an authority.
        if handler.starts_with("entity://") {
            return handler.to_string();
        }
        let trimmed = handler.trim_start_matches('/');
        format!("entity://{}/{}", self.source_peer_id, trimmed)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<'a> Dispatcher for PeerAimedDispatcher<'a> {
    async fn execute(
        &self,
        handler: &str,
        operation: &str,
        params: Entity,
        opts: ExecuteOptions,
    ) -> Result<HandlerResult, HandlerError> {
        let qualified = self.qualify(handler);
        (self.execute_fn)(qualified, operation.to_string(), params, opts).await
    }
}

// ---------------------------------------------------------------------------
// HandlerContext (§6.8 — 16 fields, reviewed ceiling)
// ---------------------------------------------------------------------------

/// Execution context provided to handlers at dispatch time.
///
/// Contains the spec-defined inputs (§6.8) plus dispatch/capability/bounds
/// support fields. The 16-field count is a reviewed ceiling per CLAUDE.md
/// anti-pattern #1 — every field below should trace to either (a) a spec
/// requirement, (b) a dispatch necessity, (c) capability/bounds plumbing, or
/// (d) an explicitly justified extension-support hook. Reject convenience
/// additions; if an extension needs more, find a side channel.
pub struct HandlerContext {
    /// The handler's own capability grant.
    pub handler_grant: Option<CapabilityToken>,
    /// The caller's verified capability token.
    pub caller_capability: Option<CapabilityToken>,
    /// The EXECUTE entity (full request).
    pub execute: Entity,
    /// The params entity extracted from the EXECUTE (§3.4).
    /// Handlers decode `params.data` for their specific fields.
    pub params: Entity,
    /// The matched handler pattern prefix.
    pub pattern: String,
    /// URI portion after the pattern.
    pub suffix: String,
    /// Resource target from EXECUTE (may be None).
    pub resource_target: Option<entity_capability::ResourceTarget>,
    /// Author identity hash.
    pub author: Option<Hash>,
    /// Base58 peer-id of the **authenticated connection peer** that delivered
    /// this EXECUTE — distinct from `author` (who *signed* the inner request).
    /// Populated from the connection's verified `remote_peer_id` for inbound
    /// wire dispatch; `None` for in-process / internal sub-dispatches. RELAY
    /// §2.2 uses this for `put_by` placement-identity: on a cross-peer relay
    /// dispatch the placer is the connecting peer, not the wire-author.
    pub session_peer_id: Option<String>,
    /// Request ID for correlation.
    pub request_id: String,
    /// The operation name from the EXECUTE message.
    pub operation: String,
    /// Handler-to-handler dispatch function (set by connection dispatcher).
    pub execute_fn: Option<ExecuteFn>,
    /// Entities included in the envelope (hash → entity).
    pub included: HashMap<Hash, Entity>,
    /// The specific grant entry that authorized this request.
    /// Handlers needing grant-level constraints (e.g., query handler)
    /// inspect this to access `constraints` field.
    pub matching_grant: Option<entity_capability::GrantEntry>,
    /// Content hash of the caller's capability token entity.
    /// Used by extensions (e.g., history) to record authorization provenance.
    pub capability_hash: Option<Hash>,
    /// Content hash of the handler's own grant entity (from `system/capability/grants/{pattern}`).
    /// Available for per-write capability selection (§6.8 write authorization).
    pub handler_grant_hash: Option<Hash>,
    /// Execution bounds — TTL, budget, chain_id, visited (§5.9).
    /// chain_id correlates writes across a handler chain.
    pub bounds: Option<Bounds>,
    /// True when this dispatch originated from an inbound wire EXECUTE
    /// (cross-peer request); false for locally-initiated requests and
    /// internal sub-dispatches. Used by receiver-local ops to refuse
    /// cross-peer invocation per PROPOSAL-CONVERGENT-MIRRORING §2.3 D4
    /// (the receiver-local reconcile contract's MUST guard). The reads-
    /// local-state ops (e.g., `revision:fetch-diff`, future `tree:mirror`)
    /// reject with 400 `invalid_dispatch` when this is true, since they
    /// would otherwise read the executor's local state on behalf of a
    /// remote caller — the trap that sank the original
    /// PROPOSAL-REVISION-DIFF-SINCE-LOCAL-HEAD POC.
    pub is_external: bool,
}

impl HandlerContext {
    /// Start a builder with the two truly-required fields. Every dispatch
    /// site needs at minimum an EXECUTE entity and a params entity (§3.4
    /// — params is extracted from EXECUTE.data). Everything else is either
    /// optional or has a sensible default (empty string / empty map /
    /// None) — the builder applies those defaults so callers only set the
    /// fields they actually have data for.
    ///
    /// Replaces the bare struct-literal construction that previously forced
    /// every new field to churn N callsites — see CLAUDE.md anti-pattern #1.
    pub fn builder(execute: Entity, params: Entity) -> HandlerContextBuilder {
        HandlerContextBuilder {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            pattern: String::new(),
            suffix: String::new(),
            resource_target: None,
            author: None,
            session_peer_id: None,
            request_id: String::new(),
            operation: String::new(),
            execute_fn: None,
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        }
    }
}

/// Builder for [`HandlerContext`]. Construct with [`HandlerContext::builder`]
/// (passing the two required entities); chain setters for any optional
/// fields the dispatch site has; call `.build()` to materialize the context.
pub struct HandlerContextBuilder {
    handler_grant: Option<CapabilityToken>,
    caller_capability: Option<CapabilityToken>,
    execute: Entity,
    params: Entity,
    pattern: String,
    suffix: String,
    resource_target: Option<entity_capability::ResourceTarget>,
    author: Option<Hash>,
    session_peer_id: Option<String>,
    request_id: String,
    operation: String,
    execute_fn: Option<ExecuteFn>,
    included: HashMap<Hash, Entity>,
    matching_grant: Option<entity_capability::GrantEntry>,
    capability_hash: Option<Hash>,
    handler_grant_hash: Option<Hash>,
    bounds: Option<Bounds>,
    is_external: bool,
}

impl HandlerContextBuilder {
    pub fn handler_grant(mut self, v: CapabilityToken) -> Self {
        self.handler_grant = Some(v);
        self
    }
    /// Base58 peer-id of the authenticated connection peer (RELAY §2.2).
    pub fn session_peer_id(mut self, v: impl Into<String>) -> Self {
        self.session_peer_id = Some(v.into());
        self
    }
    pub fn caller_capability(mut self, v: CapabilityToken) -> Self {
        self.caller_capability = Some(v);
        self
    }
    pub fn pattern(mut self, v: impl Into<String>) -> Self {
        self.pattern = v.into();
        self
    }
    pub fn suffix(mut self, v: impl Into<String>) -> Self {
        self.suffix = v.into();
        self
    }
    pub fn resource_target(mut self, v: entity_capability::ResourceTarget) -> Self {
        self.resource_target = Some(v);
        self
    }
    pub fn author(mut self, v: Hash) -> Self {
        self.author = Some(v);
        self
    }
    pub fn request_id(mut self, v: impl Into<String>) -> Self {
        self.request_id = v.into();
        self
    }
    pub fn operation(mut self, v: impl Into<String>) -> Self {
        self.operation = v.into();
        self
    }
    pub fn execute_fn(mut self, v: ExecuteFn) -> Self {
        self.execute_fn = Some(v);
        self
    }
    pub fn included(mut self, v: HashMap<Hash, Entity>) -> Self {
        self.included = v;
        self
    }
    pub fn matching_grant(mut self, v: entity_capability::GrantEntry) -> Self {
        self.matching_grant = Some(v);
        self
    }
    pub fn capability_hash(mut self, v: Hash) -> Self {
        self.capability_hash = Some(v);
        self
    }
    pub fn handler_grant_hash(mut self, v: Hash) -> Self {
        self.handler_grant_hash = Some(v);
        self
    }
    pub fn bounds(mut self, v: Bounds) -> Self {
        self.bounds = Some(v);
        self
    }
    /// Mark this context as originating from an inbound wire EXECUTE
    /// (cross-peer). Receiver-local ops use this to refuse cross-peer
    /// dispatch (PROPOSAL-CONVERGENT-MIRRORING §2.3 D4).
    pub fn is_external(mut self, v: bool) -> Self {
        self.is_external = v;
        self
    }

    pub fn build(self) -> HandlerContext {
        HandlerContext {
            handler_grant: self.handler_grant,
            caller_capability: self.caller_capability,
            execute: self.execute,
            params: self.params,
            pattern: self.pattern,
            suffix: self.suffix,
            resource_target: self.resource_target,
            author: self.author,
            session_peer_id: self.session_peer_id,
            request_id: self.request_id,
            operation: self.operation,
            execute_fn: self.execute_fn,
            included: self.included,
            matching_grant: self.matching_grant,
            capability_hash: self.capability_hash,
            handler_grant_hash: self.handler_grant_hash,
            bounds: self.bounds,
            is_external: self.is_external,
        }
    }
}

// ---------------------------------------------------------------------------
// AttestationStore — identity-binding lookup for the cap-verifier
// (EXTENSION-IDENTITY §10.1 / §12.3)
// ---------------------------------------------------------------------------

/// Result of an identity-cert lookup for a peer's identity hash.
///
/// Per EXTENSION-IDENTITY v3.2 §10.1 / §12.3, an inbound EXECUTE's author
/// is identified by a `system/peer` content hash. To make a trust
/// judgment ("is this peer an attested agent under some identity?"), the
/// verifier consults an `AttestationStore` that scans
/// `system/attestation` entities with `properties.kind = "identity-cert"`
/// and `properties.function = "agent"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationStatus {
    /// The peer is attested as an agent under an identity. `public_identity`
    /// is the issuer's hash (the controller in 3-key default; the
    /// identifier in 4-key advanced). `attestation_hash` is the
    /// `identity-cert` entity's content hash, for audit trails.
    Attested {
        public_identity: Hash,
        attestation_hash: Hash,
    },
    /// No live agent cert found in the local store.
    NotAttested,
}

/// Read-only lookup of identity attestations for cap verification
/// (EXTENSION-IDENTITY v3.2 §10.1 / §12.3).
///
/// The cap-chain verifier in `core/protocol` consults this trait via the
/// peer at dispatch time to determine whether an EXECUTE's author has a
/// live `identity-cert(function="agent")` backing it. Default impl
/// (`NoopAttestationStore`) returns `NotAttested` for every lookup —
/// installed when the identity extension isn't enabled.
///
/// **Integration status:** the trait is wired into PeerBuilder and exposed
/// via `Peer::lookup_attestation()`. Enforcement at `verify_request` is
/// NOT yet wired pending architect confirmation of the cache-miss policy
/// defaults; tracked in `docs/BACKLOG.md`.
pub trait AttestationStore: Send + Sync {
    /// Look up whether `peer_identity_hash` has a live
    /// `identity-cert(function="agent")` with `attested == peer_identity_hash`.
    fn lookup(&self, peer_identity_hash: &Hash) -> AttestationStatus;
}

/// No-op `AttestationStore` — every lookup returns `NotAttested`.
/// Installed when no identity extension provides an impl.
pub struct NoopAttestationStore;

impl AttestationStore for NoopAttestationStore {
    fn lookup(&self, _peer_identity_hash: &Hash) -> AttestationStatus {
        AttestationStatus::NotAttested
    }
}

// ---------------------------------------------------------------------------
// HandlerResult
// ---------------------------------------------------------------------------

/// Result returned by a handler.
pub struct HandlerResult {
    /// HTTP-like status code.
    pub status: u32,
    /// Result entity (for success) or error entity.
    pub result: Entity,
    /// Extra entities to include in the response envelope (hash → entity).
    /// Used when the result references entities by hash that clients need.
    pub included: HashMap<Hash, Entity>,
}

impl HandlerResult {
    pub fn ok(result: Entity) -> Self {
        Self {
            status: STATUS_OK,
            result,
            included: HashMap::new(),
        }
    }

    pub fn error(status: u32, result: Entity) -> Self {
        Self {
            status,
            result,
            included: HashMap::new(),
        }
    }

    /// Create a result with extra entities to include in the response envelope.
    pub fn ok_with_included(result: Entity, included: HashMap<Hash, Entity>) -> Self {
        Self {
            status: STATUS_OK,
            result,
            included,
        }
    }
}

/// Build a `system/protocol/error` entity carrying `code` and `message`.
///
/// Shared by every handler that returns error results — keeps the wire shape
/// in one place so extensions can't drift on field names or ECF encoding.
pub fn error_entity(code: &str, message: &str) -> Entity {
    let data = to_ecf(&Value::Map(vec![
        (text("code"), text(code)),
        (text("message"), text(message)),
    ]));
    Entity::new(TYPE_ERROR, data).expect("error entity")
}

/// Decode a `system/protocol/error` entity into `(code, message)`.
///
/// Returns `None` when `entity_type` is not `system/protocol/error`, so callers
/// can distinguish "structured error body" from "result with non-2xx status
/// but a different (e.g., domain-specific) entity type". On a malformed
/// payload, returns `Some((None, None))` rather than failing — the canonical
/// SDK error mapping then falls back to caller-supplied context.
pub fn decode_error_entity(entity: &Entity) -> Option<(Option<String>, Option<String>)> {
    if entity.entity_type != TYPE_ERROR {
        return None;
    }
    let v: Value = match ciborium::from_reader(entity.data.as_slice()) {
        Ok(v) => v,
        Err(_) => return Some((None, None)),
    };
    let map = match v {
        Value::Map(m) => m,
        _ => return Some((None, None)),
    };
    let mut code: Option<String> = None;
    let mut message: Option<String> = None;
    for (k, val) in map {
        if let Value::Text(key) = k {
            match (key.as_str(), val) {
                ("code", Value::Text(s)) => code = Some(s),
                ("message", Value::Text(s)) => message = Some(s),
                _ => {}
            }
        }
    }
    Some((code, message))
}

// ---------------------------------------------------------------------------
// Handler registry
// ---------------------------------------------------------------------------

/// Registry mapping patterns to handler instances.
///
/// Handlers are registered by pattern and looked up by longest prefix match.
pub struct HandlerRegistry {
    handlers: RwLock<BTreeMap<String, Arc<dyn Handler>>>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(BTreeMap::new()),
        }
    }

    /// Register a handler at its pattern.
    pub fn register(&self, handler: Arc<dyn Handler>) {
        let pattern = handler.pattern().to_string();
        self.handlers.write().unwrap().insert(pattern, handler);
    }

    /// Unregister a handler by pattern.
    pub fn unregister(&self, pattern: &str) -> bool {
        self.handlers.write().unwrap().remove(pattern).is_some()
    }

    /// Look up a handler by exact pattern.
    pub fn get(&self, pattern: &str) -> Option<Arc<dyn Handler>> {
        self.handlers.read().unwrap().get(pattern).cloned()
    }

    /// List all registered patterns.
    pub fn patterns(&self) -> Vec<String> {
        self.handlers.read().unwrap().keys().cloned().collect()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Handler resolution (§6.6 — longest prefix match)
// ---------------------------------------------------------------------------

/// Result of resolving a handler from a path (V7 §6.6).
///
/// Per §6.6 the tree is the source of truth. A resolved handler may be:
///   - Compiled: registry has an in-memory `Handler` impl at `pattern`.
///     `handler` is `Some`, `manifest` is the tree entity if the manifest is
///     also stored (typically yes — bootstrap seeds it; can be `None` for
///     handlers added before their manifest lands in the tree).
///   - Tree-only: tree has a `system/handler` entity at `pattern` but no
///     compiled implementation in the registry. Caller (e.g., dispatcher)
///     inspects `manifest.data.expression_path` to route through the
///     entity-native pathway (V7 §6.6 / EXTENSION-COMPUTE).
pub struct ResolvedHandler {
    /// Compiled handler implementation, if one is registered for this pattern.
    /// `None` means the tree carries the manifest but no compiled code is
    /// available — entity-native dispatch is the expected path.
    pub handler: Option<Arc<dyn Handler>>,
    /// The `system/handler` manifest entity loaded from the tree, if present.
    /// Carries `expression_path` and other manifest fields used by entity-native
    /// dispatch. `None` for early-bootstrap registry-only resolutions.
    pub manifest: Option<Entity>,
    /// The matched pattern prefix (e.g., "system/tree").
    pub pattern: String,
    /// The URI suffix after the pattern (e.g., "/instances/backup").
    pub suffix: String,
}

/// Resolve a handler by walking backward through path segments (V7 §6.6).
///
/// At each prefix, longest-first:
///   1. Read the tree at the prefix. If it holds a `system/handler` entity,
///      record the manifest.
///   2. If the registry has a compiled handler at the same prefix, return
///      a compiled `ResolvedHandler` (compiled takes priority per §6.5 —
///      tree manifest is still recorded for handlers that need it).
///   3. Else if the tree manifest exists, return a tree-only `ResolvedHandler`
///      (entity-native or any handler whose code lives in the tree).
///   4. Else if the registry has a handler at the prefix (bootstrap state
///      before the manifest lands in the tree), return a registry-only
///      `ResolvedHandler`.
///
/// First successful prefix wins (longest-prefix match).
pub fn resolve_handler(
    handler_path: &str,
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    registry: &HandlerRegistry,
) -> Option<ResolvedHandler> {
    let segments: Vec<&str> = handler_path.split('/').collect();

    tracing::trace!(handler_path = %handler_path, segments = segments.len(), "resolving handler");

    for i in (1..=segments.len()).rev() {
        let prefix = segments[..i].join("/");
        let suffix = if prefix.len() < handler_path.len() {
            handler_path[prefix.len()..].to_string()
        } else {
            String::new()
        };

        // 1. Tree at this prefix — record the manifest if present and typed correctly.
        let manifest = location_index
            .get(&prefix)
            .and_then(|h| content_store.get(&h))
            .filter(|e| e.entity_type == entity_types::TYPE_HANDLER);

        // 2. Registry at this prefix — compiled implementations.
        let registered = registry.get(&prefix);

        match (registered, manifest) {
            (Some(handler), manifest) => {
                tracing::trace!(
                    handler_path = %handler_path,
                    resolved_pattern = %prefix,
                    suffix = %suffix,
                    handler_name = %handler.name(),
                    source = if manifest.is_some() { "tree+registry" } else { "registry" },
                    "handler resolved"
                );
                return Some(ResolvedHandler {
                    handler: Some(handler),
                    manifest,
                    pattern: prefix,
                    suffix,
                });
            }
            (None, Some(manifest)) => {
                // Tree-only: no compiled code, but the tree carries a system/handler
                // entity. Caller routes via manifest.data.expression_path (V7 §6.6).
                tracing::trace!(
                    handler_path = %handler_path,
                    resolved_pattern = %prefix,
                    suffix = %suffix,
                    source = "tree-only",
                    "handler resolved (tree-only manifest)"
                );
                return Some(ResolvedHandler {
                    handler: None,
                    manifest: Some(manifest),
                    pattern: prefix,
                    suffix,
                });
            }
            (None, None) => {
                // Neither registered nor in tree — keep walking.
                continue;
            }
        }
    }

    tracing::trace!(handler_path = %handler_path, "no handler found");
    None
}

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("handler error: {0}")]
    Internal(String),

    #[error("operation not supported: {0}")]
    NotSupported(String),

    #[error("invalid params: {0}")]
    InvalidParams(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    struct TestHandler {
        pat: String,
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl Handler for TestHandler {
        async fn handle(&self, _ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
            let data = entity_ecf::to_ecf(&entity_ecf::text("ok"));
            let result = Entity::new("test/result", data).unwrap();
            Ok(HandlerResult::ok(result))
        }
        fn pattern(&self) -> &str {
            &self.pat
        }
        fn name(&self) -> &str {
            "test"
        }
        fn operations(&self) -> &[&str] {
            &["get"]
        }
    }

    fn test_handler(pattern: &str) -> Arc<dyn Handler> {
        Arc::new(TestHandler {
            pat: pattern.to_string(),
        })
    }

    // --- Registry tests ---

    #[test]
    fn test_registry_register_get() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("system/tree"));
        assert!(reg.get("system/tree").is_some());
        assert!(reg.get("system/handler").is_none());
    }

    #[test]
    fn test_registry_unregister() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("system/tree"));
        assert!(reg.unregister("system/tree"));
        assert!(reg.get("system/tree").is_none());
        assert!(!reg.unregister("system/tree"));
    }

    #[test]
    fn test_registry_patterns() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("system/tree"));
        reg.register(test_handler("system/handler"));
        let patterns = reg.patterns();
        assert_eq!(patterns.len(), 2);
    }

    // --- Resolve handler tests ---

    #[test]
    fn test_resolve_exact_match_registry() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("system/tree"));
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();
        let result = resolve_handler("system/tree", &store, &index, &reg).unwrap();
        assert_eq!(result.pattern, "system/tree");
        assert_eq!(result.suffix, "");
    }

    #[test]
    fn test_resolve_prefix_match() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("system/tree"));
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();
        let result =
            resolve_handler("system/tree/instances/backup", &store, &index, &reg).unwrap();
        assert_eq!(result.pattern, "system/tree");
        assert_eq!(result.suffix, "/instances/backup");
    }

    #[test]
    fn test_resolve_longest_prefix() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("local"));
        reg.register(test_handler("local/files"));
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();
        let result = resolve_handler("local/files/readme.md", &store, &index, &reg).unwrap();
        assert_eq!(result.pattern, "local/files");
        assert_eq!(result.suffix, "/readme.md");
    }

    #[test]
    fn test_resolve_no_match() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("system/tree"));
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();
        assert!(resolve_handler("local/processes/shell", &store, &index, &reg).is_none());
    }

    #[test]
    fn test_resolve_with_tree() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("system/tree"));
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();

        // Put a handler entity in the tree (normalized: interface path reference only)
        let handler_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "interface" => entity_ecf::text("system/handler/system/tree")
        });
        let handler_entity =
            Entity::new(entity_types::TYPE_HANDLER, handler_data).unwrap();
        let hash = store.put(handler_entity).unwrap();
        index.set("system/tree", hash);

        let result = resolve_handler("system/tree", &store, &index, &reg).unwrap();
        assert_eq!(result.pattern, "system/tree");
        assert!(result.handler.is_some(), "compiled handler must take priority");
        assert!(result.manifest.is_some(), "tree manifest also recorded");
    }

    #[test]
    fn test_resolve_tree_only_no_compiled_handler() {
        // V7 §6.6: tree is the source of truth. A handler entity in the tree
        // without a compiled implementation in the registry MUST resolve so
        // entity-native dispatch can take over. Regression for the issue
        // caught by the Go validator — resolver previously
        // logged "tree has handler entity but no registered handler" and
        // returned None, breaking entity-native dispatch entirely.
        let reg = HandlerRegistry::new();
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();

        let handler_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "expression_path" => entity_ecf::text("system/validate/entity-native/expr"),
            "interface" => entity_ecf::text("system/handler/system/validate/entity-native/multi")
        });
        let handler_entity =
            Entity::new(entity_types::TYPE_HANDLER, handler_data).unwrap();
        let hash = store.put(handler_entity).unwrap();
        index.set("system/validate/entity-native/multi", hash);

        let result = resolve_handler(
            "system/validate/entity-native/multi",
            &store,
            &index,
            &reg,
        )
        .expect("tree-only handler must resolve per V7 §6.6");
        assert_eq!(result.pattern, "system/validate/entity-native/multi");
        assert!(result.handler.is_none(), "no compiled handler — tree-only");
        assert!(result.manifest.is_some(), "manifest must be carried for entity-native dispatch");
    }

    #[test]
    fn test_resolve_compiled_takes_priority_over_tree_at_same_prefix() {
        // V7 §6.5: compiled handlers in the registry take priority over
        // tree-walked entity-native handlers at the same prefix.
        let reg = HandlerRegistry::new();
        reg.register(test_handler("system/tree"));
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();

        let handler_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "expression_path" => entity_ecf::text("some/expr/path")
        });
        let handler_entity =
            Entity::new(entity_types::TYPE_HANDLER, handler_data).unwrap();
        let hash = store.put(handler_entity).unwrap();
        index.set("system/tree", hash);

        let result = resolve_handler("system/tree", &store, &index, &reg).unwrap();
        assert!(result.handler.is_some(), "compiled wins at same prefix");
        assert!(result.manifest.is_some(), "manifest still recorded for inspection");
    }

    // --- Absolute path resolution tests ---

    #[test]
    fn test_resolve_absolute_path() {
        // Absolute paths start with "/" — splitting produces ["", "peer", "system", "tree"]
        // The backward walk must handle the empty first segment correctly.
        let reg = HandlerRegistry::new();
        reg.register(test_handler("/peer123/system/tree"));
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();
        let result = resolve_handler("/peer123/system/tree", &store, &index, &reg).unwrap();
        assert_eq!(result.pattern, "/peer123/system/tree");
        assert_eq!(result.suffix, "");
    }

    #[test]
    fn test_resolve_absolute_path_with_suffix() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("/peer123/system/tree"));
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();
        let result =
            resolve_handler("/peer123/system/tree/data/readme", &store, &index, &reg).unwrap();
        assert_eq!(result.pattern, "/peer123/system/tree");
        assert_eq!(result.suffix, "/data/readme");
    }

    #[test]
    fn test_resolve_absolute_no_match() {
        let reg = HandlerRegistry::new();
        reg.register(test_handler("/peerA/system/tree"));
        let store = MemoryContentStore::new();
        let index = MemoryLocationIndex::new();
        // Different peer prefix — should not match
        assert!(resolve_handler("/peerB/system/tree", &store, &index, &reg).is_none());
    }

    // --- HandlerResult tests ---

    #[test]
    fn test_handler_result_ok() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("result"));
        let entity = Entity::new("test/result", data).unwrap();
        let result = HandlerResult::ok(entity);
        assert_eq!(result.status, STATUS_OK);
    }

    #[test]
    fn test_handler_result_error() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("error"));
        let entity = Entity::new("test/error", data).unwrap();
        let result = HandlerResult::error(STATUS_NOT_FOUND, entity);
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    #[test]
    fn decode_error_entity_round_trips_code_and_message() {
        let entity = error_entity("sensitive_path", "operator-class required");
        let (code, message) = decode_error_entity(&entity).expect("system/protocol/error decodes");
        assert_eq!(code.as_deref(), Some("sensitive_path"));
        assert_eq!(message.as_deref(), Some("operator-class required"));
    }

    #[test]
    fn decode_error_entity_returns_none_for_non_error_type() {
        let entity = Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        assert!(decode_error_entity(&entity).is_none());
    }

    #[test]
    fn decode_error_entity_some_none_on_malformed_body() {
        // Right type, wrong shape — decode returns Some((None, None))
        // so the SDK boundary falls back to caller context rather than
        // surfacing a panic or silently dropping the 4xx status.
        let entity = Entity::new(
            TYPE_ERROR,
            entity_ecf::to_ecf(&entity_ecf::text("not a map")),
        )
        .unwrap();
        let (code, message) = decode_error_entity(&entity).expect("type matches");
        assert!(code.is_none());
        assert!(message.is_none());
    }
}
