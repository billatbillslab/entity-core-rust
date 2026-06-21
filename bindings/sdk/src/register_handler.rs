//! Dynamic handler registration — SDK §11.5 primitive.
//!
//! `PeerContext::register_handler(spec, body)` couples the protocol-side
//! declaration (manifest / interface / grant tree entities) with the
//! implementation-side binding (callable in the handler dispatch index).
//!
//! Write order (§11.5.1, post-normalization):
//! 1. Interface entity at `/{pid}/system/handler/{bare}` — public contract.
//! 2. Handler entity at `/{pid}/{bare}` — dispatch target with `interface` path ref.
//! 3. Grant at `/{pid}/system/capability/grants/{bare}` (if `internal_scope` set).
//! 4. Dispatch index entry.
//!
//! `RegisteredHandler::close` (also `impl Drop`) reverses the order:
//! dispatch index first, then grant, handler, interface. Close is idempotent.
//! Type definitions installed via `types` are NOT removed on close — they
//! have independent lifecycle (§11.5.2).

// SDK module — see note in src/sdk.rs about intentional public API
// items that the current binary doesn't consume.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use entity_capability::{CapabilityToken, GrantEntry};
use entity_crypto::Keypair;
use entity_ecf::{text, Value};
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerRegistry, HandlerResult,
};
use entity_store::{ContentStore, LocationIndex};

use crate::sdk::{PeerContext, SdkError};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Input describing one operation accepted by a dynamic handler.
#[derive(Debug, Clone)]
pub struct OperationSpec {
    pub name: String,
    pub input_type: Option<String>,
    pub output_type: Option<String>,
}

impl OperationSpec {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            input_type: None,
            output_type: None,
        }
    }

    pub fn with_input(mut self, ty: impl Into<String>) -> Self {
        self.input_type = Some(ty.into());
        self
    }

    pub fn with_output(mut self, ty: impl Into<String>) -> Self {
        self.output_type = Some(ty.into());
        self
    }
}

/// Registration input for [`PeerContext::register_handler`] (§11.5).
///
/// `pattern` is a **bare** pattern (no leading slash) — the SDK qualifies
/// it to `/{peer_id}/{pattern}` internally.
#[derive(Debug, Clone)]
pub struct HandlerSpec {
    pub pattern: String,
    pub name: String,
    pub description: Option<String>,
    pub operations: Vec<OperationSpec>,
    pub internal_scope: Option<Vec<GrantEntry>>,
}

impl HandlerSpec {
    pub fn new(
        pattern: impl Into<String>,
        name: impl Into<String>,
        operations: Vec<OperationSpec>,
    ) -> Self {
        Self {
            pattern: pattern.into(),
            name: name.into(),
            description: None,
            operations,
            internal_scope: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_internal_scope(mut self, scope: Vec<GrantEntry>) -> Self {
        self.internal_scope = Some(scope);
        self
    }
}

/// Language-native handler body — a closure returning a future.
///
/// The SDK wraps this in an internal adapter that implements the core
/// [`Handler`] trait. `'static` lifetime and `Send + Sync` are required
/// for dispatch from arbitrary runtime contexts.
pub type HandlerBody = Arc<
    dyn Fn(
            &HandlerContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<HandlerResult, HandlerError>> + Send>,
        > + Send
        + Sync
        + 'static,
>;

/// Handle returned by [`PeerContext::register_handler`].
///
/// Dropping this handle unregisters both sides — dispatch index first
/// (stops accepting dispatch immediately), then the tree entries
/// (interface, handler, grant). Close is idempotent.
///
/// Type definitions installed via the spec are NOT removed on close —
/// they have independent lifecycle (§11.5.2).
#[must_use = "dropping this handle unregisters the handler immediately"]
pub struct RegisteredHandler {
    /// Qualified dispatch path: `/{peer_id}/{bare_pattern}`.
    pattern: String,
    /// Qualified interface path: `/{peer_id}/system/handler/{bare_pattern}`.
    interface_path: String,
    /// Qualified grant path — `Some` only if `internal_scope` was set.
    grant_path: Option<String>,
    peer_handler_registry: Arc<HandlerRegistry>,
    location_index: Arc<dyn LocationIndex>,
    closed: AtomicBool,
}

impl RegisteredHandler {
    /// The qualified handler dispatch pattern.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// The qualified interface entity path.
    pub fn interface_path(&self) -> &str {
        &self.interface_path
    }

    /// Explicit close. Idempotent — safe to call more than once; second
    /// and later calls are no-ops. Drop also triggers close.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // 1. Dispatch index first — stop accepting dispatch immediately.
        self.peer_handler_registry.unregister(&self.pattern);
        // 2. Tree entries in reverse write order: grant, handler, interface.
        if let Some(gp) = &self.grant_path {
            self.location_index.remove(gp);
        }
        self.location_index.remove(&self.pattern);
        self.location_index.remove(&self.interface_path);
    }
}

impl std::fmt::Debug for RegisteredHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredHandler")
            .field("pattern", &self.pattern)
            .field("interface_path", &self.interface_path)
            .field("grant_path", &self.grant_path)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for RegisteredHandler {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------
// Body adapter — wraps a closure body into the core Handler trait
// ---------------------------------------------------------------------------

struct BodyAdapter {
    pattern: String,
    name: String,
    /// Leaked static references to own the operation names so the
    /// `Handler::operations` trait method can return `&[&'static str]`.
    /// The leak is intentional: registration is rare and the handler
    /// typically lives as long as the process. Each registration leaks
    /// `sum(op.name.len() + 24)` bytes — negligible in practice.
    operations: Box<[&'static str]>,
    internal_scope: Option<Vec<GrantEntry>>,
    body: HandlerBody,
}

impl BodyAdapter {
    fn new(
        pattern: String,
        name: String,
        operation_names: Vec<String>,
        internal_scope: Option<Vec<GrantEntry>>,
        body: HandlerBody,
    ) -> Self {
        let operations: Box<[&'static str]> = operation_names
            .into_iter()
            .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
            .collect();
        Self {
            pattern,
            name,
            operations,
            internal_scope,
            body,
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Handler for BodyAdapter {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        (self.body)(ctx).await
    }

    fn pattern(&self) -> &str {
        &self.pattern
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn operations(&self) -> &[&str] {
        &self.operations
    }

    fn internal_scope(&self) -> Option<Vec<GrantEntry>> {
        self.internal_scope.clone()
    }
}

// ---------------------------------------------------------------------------
// register_handler method
// ---------------------------------------------------------------------------

impl PeerContext {
    /// Register a dynamic handler at runtime per SDK-OPERATIONS §11.5.
    ///
    /// Writes three tree entities (interface, handler, optional grant) and
    /// one dispatch-index entry — the four mutations enumerated in §11.5.1.
    /// Tree writes first, dispatch-index write last; if any step fails, all
    /// prior writes are reverted (§11.5.4).
    ///
    /// On success, the returned [`RegisteredHandler`] handle owns the
    /// lifecycle: dropping it (or calling `close`) unregisters both sides.
    ///
    /// # Errors
    ///
    /// - **400** `invalid_handler_spec` — empty pattern, leading-slash pattern,
    ///   or empty operations list.
    /// - **409** `pattern_collision` — a handler is already registered at the
    ///   pattern (either in the tree or the dispatch index).
    /// - **500** `partial_registration_failure` — a write step failed after
    ///   compensation. The tree and dispatch index are left clean.
    pub fn register_handler(
        &self,
        spec: HandlerSpec,
        body: HandlerBody,
    ) -> Result<RegisteredHandler, SdkError> {
        validate_spec(&spec)?;

        let pid = self.peer_id();
        let bare = &spec.pattern;
        let interface_rel = format!("system/handler/{}", bare);
        let interface_path = format!("/{}/{}", pid, interface_rel);
        let handler_path = format!("/{}/{}", pid, bare);
        let grant_path = format!("/{}/system/capability/grants/{}", pid, bare);

        let peer = self.peer();
        let index = peer.location_index().clone();
        let registry = peer.handler_registry().clone();
        let store = peer.content_store().clone();

        // Collision check — both sides of the invariant.
        if index.get(&handler_path).is_some() || registry.get(&handler_path).is_some() {
            return Err(SdkError::Conflict {
                status: 409,
                code: Some("pattern_collision".into()),
                message: format!("pattern_collision: {}", bare),
            });
        }

        // 1. Interface entity — public contract, single source of truth for
        //    pattern/name/operations.
        let interface_entity = build_interface_entity(&spec).map_err(internal_err)?;
        let iface_hash = store.put(interface_entity).map_err(internal_err)?;
        index.set(&interface_path, iface_hash);

        // 2. Handler entity — dispatch target, references interface by path.
        let handler_entity = match build_handler_entity(&interface_rel) {
            Ok(e) => e,
            Err(e) => {
                index.remove(&interface_path);
                return Err(internal_err(e));
            }
        };
        let handler_hash = match store.put(handler_entity) {
            Ok(h) => h,
            Err(e) => {
                index.remove(&interface_path);
                return Err(internal_err(e.to_string()));
            }
        };
        index.set(&handler_path, handler_hash);

        // 3. Grant — only if internal_scope declared. Absent scope means the
        //    handler explicitly cannot call other handlers from its body (§11.5.3).
        let grant_written = if let Some(scope) = &spec.internal_scope {
            match write_handler_grant(
                scope.clone(),
                peer.keypair()
                    .as_ed25519()
                    .expect("entity-sdk peers are Ed25519-only (Ed448 backends use core PeerBuilder)"),
                &store,
                &index,
                &grant_path,
            ) {
                Ok(()) => true,
                Err(e) => {
                    index.remove(&handler_path);
                    index.remove(&interface_path);
                    return Err(internal_err(e));
                }
            }
        } else {
            false
        };

        // 4. Dispatch index — final step. If this failed we would compensate
        //    the tree writes, but `HandlerRegistry::register` is infallible
        //    today (pure in-memory BTreeMap insert under a RwLock), so no
        //    compensation path is reachable here.
        let adapter = Arc::new(BodyAdapter::new(
            handler_path.clone(),
            spec.name,
            spec.operations.into_iter().map(|o| o.name).collect(),
            spec.internal_scope,
            body,
        ));
        registry.register(adapter);

        // Increment generation so watchers see the tree mutations.
        self.bump_generation();

        Ok(RegisteredHandler {
            pattern: handler_path,
            interface_path,
            grant_path: if grant_written { Some(grant_path) } else { None },
            peer_handler_registry: registry,
            location_index: index,
            closed: AtomicBool::new(false),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_spec(spec: &HandlerSpec) -> Result<(), SdkError> {
    if spec.pattern.is_empty() {
        return Err(SdkError::BadRequest {
            status: 400,
            code: Some("invalid_handler_spec".into()),
            message: "invalid_handler_spec: empty pattern".into(),
        });
    }
    if spec.pattern.starts_with('/') {
        return Err(SdkError::BadRequest {
            status: 400,
            code: Some("invalid_handler_spec".into()),
            message: "invalid_handler_spec: bare pattern must not start with '/'".into(),
        });
    }
    if spec.operations.is_empty() {
        return Err(SdkError::BadRequest {
            status: 400,
            code: Some("invalid_handler_spec".into()),
            message: "invalid_handler_spec: empty operations list".into(),
        });
    }
    Ok(())
}

fn internal_err(e: impl std::fmt::Display) -> SdkError {
    SdkError::Internal {
        status: 500,
        code: Some("partial_registration_failure".into()),
        message: format!("partial_registration_failure: {}", e),
    }
}

fn build_interface_entity(spec: &HandlerSpec) -> Result<Entity, String> {
    let operations_map = Value::Map(
        spec.operations
            .iter()
            .map(|op| {
                let mut fields: Vec<(Value, Value)> = Vec::new();
                if let Some(input) = &op.input_type {
                    fields.push((text("input_type"), text(input)));
                }
                if let Some(output) = &op.output_type {
                    fields.push((text("output_type"), text(output)));
                }
                (text(&op.name), Value::Map(fields))
            })
            .collect(),
    );

    let data = entity_ecf::to_ecf(&Value::Map(vec![
        (text("name"), text(&spec.name)),
        (text("operations"), operations_map),
        (text("pattern"), text(&spec.pattern)),
    ]));

    Entity::new(entity_types::TYPE_HANDLER_INTERFACE, data).map_err(|e| e.to_string())
}

fn build_handler_entity(interface_rel: &str) -> Result<Entity, String> {
    // Matches core bootstrap (core/peer/src/lib.rs::bootstrap_handler):
    // the handler entity stores only the interface path reference.
    // `max_scope`, `internal_scope`, and `expression_path` are declared
    // as optional on the type (V7 §3.7); the scope is separately captured
    // in the grant entity and on the Handler trait adapter.
    let data = entity_ecf::to_ecf(&Value::Map(vec![(
        text("interface"),
        text(interface_rel),
    )]));
    Entity::new(entity_types::TYPE_HANDLER, data).map_err(|e| e.to_string())
}

/// Mint and store a signed self-grant for a handler at
/// `/{pid}/system/capability/grants/{bare}`. Mirrors the core's
/// `create_handler_grant` (§6.9) — token entity + signature entity in the
/// content store, binding in the tree.
fn write_handler_grant(
    scope: Vec<GrantEntry>,
    keypair: &Keypair,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    grant_path: &str,
) -> Result<(), String> {
    let peer_entity = keypair.peer_entity().map_err(|e| e.to_string())?;
    let identity_hash = peer_entity.content_hash;

    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let cap_token = CapabilityToken {
        grants: scope,
        granter: entity_capability::Granter::Single(identity_hash),
        grantee: identity_hash, // self-grant
        parent: None,
        created_at: now_ms,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };

    let cap_entity = cap_token.to_entity().map_err(|e| e.to_string())?;
    let cap_hash = content_store
        .put(cap_entity.clone())
        .map_err(|e| e.to_string())?;

    // Sign the token (same shape as bootstrap handler grants).
    let sig_bytes = keypair.sign(&cap_entity.content_hash.to_bytes());
    let sig_data = entity_ecf::to_ecf(&Value::Map(vec![
        (text("algorithm"), text("ed25519")),
        (text("signature"), Value::Bytes(sig_bytes.to_vec())),
        (
            text("signer"),
            Value::Bytes(identity_hash.to_bytes().to_vec()),
        ),
        (
            text("target"),
            Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
        ),
    ]));
    let sig_entity =
        Entity::new(entity_entity::TYPE_SIGNATURE, sig_data).map_err(|e| e.to_string())?;
    content_store.put(sig_entity).map_err(|e| e.to_string())?;

    location_index.set(grant_path, cap_hash);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::PeerContextBuilder;
    use std::sync::Mutex;

    fn make_peer_context() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    fn noop_body() -> HandlerBody {
        Arc::new(|_ctx: &HandlerContext| {
            Box::pin(async move {
                let result_data = entity_ecf::to_ecf(&Value::Map(Vec::new()));
                let result = Entity::new("app/test/result", result_data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                Ok(HandlerResult::ok(result))
            })
        })
    }

    fn basic_spec(pattern: &str) -> HandlerSpec {
        HandlerSpec::new(
            pattern,
            "test-handler",
            vec![OperationSpec::new("ping")],
        )
    }

    #[test]
    fn register_handler_writes_all_three_entities() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let handle = ctx
            .register_handler(basic_spec("app/test/reg"), noop_body())
            .expect("register should succeed");

        let store = ctx.store();
        let iface_path = format!("/{}/system/handler/app/test/reg", pid);
        let handler_path = format!("/{}/app/test/reg", pid);

        assert!(
            store.get(&iface_path).is_some(),
            "interface entity written"
        );
        let handler_entity = store.get(&handler_path).expect("handler entity written");
        assert_eq!(handler_entity.entity_type, entity_types::TYPE_HANDLER);
        assert_eq!(handle.pattern(), handler_path);
        assert_eq!(handle.interface_path(), iface_path);
    }

    #[test]
    fn register_handler_without_internal_scope_skips_grant() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let _h = ctx
            .register_handler(basic_spec("app/test/nogr"), noop_body())
            .expect("register should succeed");
        let grant_path = format!("/{}/system/capability/grants/app/test/nogr", pid);
        assert!(
            ctx.store().get(&grant_path).is_none(),
            "no grant without internal_scope"
        );
    }

    #[test]
    fn register_handler_with_internal_scope_writes_grant() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let scope = entity_capability::wildcard_handler_grant();

        let spec = HandlerSpec::new(
            "app/test/gr",
            "scoped",
            vec![OperationSpec::new("do")],
        )
        .with_internal_scope(scope);

        let _h = ctx
            .register_handler(spec, noop_body())
            .expect("register should succeed");

        let grant_path = format!("/{}/system/capability/grants/app/test/gr", pid);
        assert!(
            ctx.store().get(&grant_path).is_some(),
            "grant written when internal_scope present"
        );
    }

    #[test]
    fn register_handler_pattern_collision_returns_409() {
        let ctx = make_peer_context();
        let _h = ctx
            .register_handler(basic_spec("app/test/dup"), noop_body())
            .expect("first register should succeed");

        let err = ctx
            .register_handler(basic_spec("app/test/dup"), noop_body())
            .expect_err("duplicate should fail");
        assert!(matches!(err, SdkError::Conflict { status: 409, .. }));
    }

    #[test]
    fn register_handler_rejects_leading_slash_pattern() {
        let ctx = make_peer_context();
        let err = ctx
            .register_handler(basic_spec("/app/nope"), noop_body())
            .expect_err("leading-slash pattern should fail");
        assert!(matches!(err, SdkError::BadRequest { status: 400, .. }));
    }

    #[test]
    fn register_handler_rejects_empty_pattern() {
        let ctx = make_peer_context();
        let spec = HandlerSpec::new("", "n", vec![OperationSpec::new("op")]);
        let err = ctx
            .register_handler(spec, noop_body())
            .expect_err("empty pattern should fail");
        assert!(matches!(err, SdkError::BadRequest { status: 400, .. }));
    }

    #[test]
    fn register_handler_rejects_empty_operations() {
        let ctx = make_peer_context();
        let spec = HandlerSpec::new("app/test/noops", "n", vec![]);
        let err = ctx
            .register_handler(spec, noop_body())
            .expect_err("empty operations should fail");
        assert!(matches!(err, SdkError::BadRequest { status: 400, .. }));
    }

    #[test]
    fn register_handler_close_removes_tree_entries() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let handle = ctx
            .register_handler(basic_spec("app/test/close"), noop_body())
            .expect("register should succeed");
        let iface_path = handle.interface_path().to_string();
        let handler_path = handle.pattern().to_string();
        assert!(ctx.store().get(&iface_path).is_some());
        assert!(ctx.store().get(&handler_path).is_some());

        handle.close();

        assert!(
            ctx.store().get(&iface_path).is_none(),
            "interface removed on close"
        );
        assert!(
            ctx.store().get(&handler_path).is_none(),
            "handler removed on close"
        );
        let _ = pid; // suppress unused binding
    }

    #[test]
    fn register_handler_drop_closes() {
        let ctx = make_peer_context();
        let iface_path;
        let handler_path;
        {
            let handle = ctx
                .register_handler(basic_spec("app/test/drop"), noop_body())
                .expect("register should succeed");
            iface_path = handle.interface_path().to_string();
            handler_path = handle.pattern().to_string();
            assert!(ctx.store().get(&handler_path).is_some());
        } // <- drop runs here

        assert!(
            ctx.store().get(&handler_path).is_none(),
            "handler removed on drop"
        );
        assert!(
            ctx.store().get(&iface_path).is_none(),
            "interface removed on drop"
        );
    }

    #[test]
    fn register_handler_close_idempotent() {
        let ctx = make_peer_context();
        let handle = ctx
            .register_handler(basic_spec("app/test/idem"), noop_body())
            .expect("register should succeed");
        handle.close();
        handle.close(); // Second call: no-op, must not panic.
    }

    #[tokio::test]
    async fn register_handler_body_dispatches() {
        let ctx = make_peer_context();
        let called = Arc::new(Mutex::new(0u32));
        let counter = called.clone();

        let body: HandlerBody = Arc::new(move |_ctx: &HandlerContext| {
            let counter = counter.clone();
            Box::pin(async move {
                *counter.lock().unwrap() += 1;
                let data = entity_ecf::to_ecf(&Value::Map(Vec::new()));
                let result = Entity::new("app/test/pong", data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                Ok(HandlerResult::ok(result))
            })
        });

        let _h = ctx
            .register_handler(basic_spec("app/test/dispatch"), body)
            .expect("register should succeed");

        let params = Entity::new(
            "app/test/params",
            entity_ecf::to_ecf(&Value::Map(Vec::new())),
        )
        .unwrap();
        let result = ctx
            .execute(
                "app/test/dispatch",
                "ping",
                params,
                entity_handler::ExecuteOptions::default(),
            )
            .await
            .expect("execute should succeed");
        assert_eq!(result.status, 200);
        assert_eq!(*called.lock().unwrap(), 1);
    }
}
