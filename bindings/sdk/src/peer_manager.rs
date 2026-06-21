//! PeerManager — multi-peer container wrapping EntitySDK.
//!
//! Holds one EntitySDK instance and routes per-peer operations to the
//! correct PeerContext. Application-tier state (UI scrollback, connection
//! display lists, listener addresses) lives in the consuming app, not
//! here — see the egui app's `event_log_writer`, `connections`, and
//! `listener_state` modules for examples of tree-backed app state.

use std::sync::Arc;

use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_peer::{PeerConfig, PeerShared};
#[cfg(feature = "native-ws")]
use entity_peer::Peer;
use entity_store::LocationEntry;

use crate::sdk::{EntitySDK, PeerContext, PeerMetadata, QueryResults, SdkError};

/// A peer recovered from app-tier persistent storage. The keypair restores
/// the identity; the label is user-facing metadata; the optional
/// `sqlite_path` points the kernel at a SQLite-backed tree per
/// `GUIDE-PERSISTENCE.md` §1 (typically `~/.entity/peers/{name}/store.db`).
///
/// Apps own their persistence strategy (filesystem, localStorage, SQLite,
/// platform-native key store, etc.) and pass the loaded set into
/// [`PeerManager::load_persisted`].
pub struct PersistedPeer {
    pub keypair: Keypair,
    pub label: Option<String>,
    /// When `Some`, the SDK opens (or creates) this SQLite database for
    /// the peer's tree. `None` means in-memory store (state lost on
    /// restart). Always `None` on WASM (browser has no filesystem) but
    /// the field is unconditional so cross-platform constructors don't
    /// need cfg-gating.
    pub sqlite_path: Option<std::path::PathBuf>,
}

// Re-export types so existing imports from peer_manager continue to work.
pub use crate::sdk::{FieldInfo, HandlerInfo, HistoryQueryOptions, HistoryQueryResult, HistoryTransition, QueryMatch, TypeInfo};
pub use crate::subscription::SubscriptionInfo;

/// Default WebSocket listen address for native.
#[cfg(not(target_arch = "wasm32"))]
pub const DEFAULT_WS_ADDR: &str = "0.0.0.0:4041";

/// Manages one or more Peer instances.
///
/// Windows bind to a specific peer by storing its peer_id.
/// New windows default to the primary peer.
pub struct PeerManager {
    sdk: EntitySDK,
    /// Override for the platform-default connector. When `Some`, every
    /// peer created through this manager (primary in `new`, persisted
    /// in `load_persisted`, new in `create_new_peer`) uses this
    /// connector instead of the cfg-selected default. Set via
    /// `with_connector`; unset means "platform default" (WS native /
    /// browser-WS WASM / none if neither feature).
    connector_override: Option<Arc<dyn entity_peer::transport::Connector>>,
}

impl PeerManager {
    /// Create a PeerManager with a single primary peer (generated keypair, no
    /// persisted peers loaded).
    ///
    /// Apps that restore peers across runs construct the manager with this
    /// and then feed in their persisted set via [`load_persisted`](Self::load_persisted).
    pub fn new() -> Self {
        Self::with_keypair_and_optional_connector(None, None)
    }

    /// Create a PeerManager whose peers all use the given connector
    /// instead of the platform default. Use this when peers need an
    /// alternative transport — e.g., `MemoryConnector` for in-process
    /// multi-peer tests or single-process scenarios.
    pub fn with_connector(
        connector: Arc<dyn entity_peer::transport::Connector>,
    ) -> Self {
        Self::with_keypair_and_optional_connector(None, Some(connector))
    }

    /// Create a PeerManager whose primary peer uses a caller-supplied
    /// `keypair` instead of a freshly generated one — so the primary
    /// **peer-id is stable / reproducible across runs**. Use this where the
    /// peer-id is an address that must not shift run-to-run (e.g. a content
    /// *publisher* identity, so static permalinks stay valid; see the egui
    /// app's `content_site::publish`). Pairs with [`Keypair::from_seed`].
    pub fn with_keypair(keypair: Keypair) -> Self {
        Self::with_keypair_and_optional_connector(Some(keypair), None)
    }

    /// Create a PeerManager whose primary peer is backed by a durable,
    /// **main-thread IndexedDB** store (write-behind journal + checkpoint),
    /// instead of the default in-memory store.
    ///
    /// `keypair` pins the primary peer-id and is **required, not optional**:
    /// durability depends on the same peer-id mapping to the same IDB
    /// database across reloads, so the caller must supply a stable
    /// seed-derived keypair (pairs with [`Keypair::from_seed`]). `db_name`
    /// is the IndexedDB database name (typically derived from the peer-id);
    /// multiple IDB-backed peers in one origin MUST use distinct names.
    ///
    /// Async because IDB `open` + the initial replay are request-based
    /// (exactly like the OPFS worker path). After construction, reach the
    /// checkpoint handle via the primary [`PeerContext::idb_checkpoint`] and
    /// `await` it on identity/destructive ops before acknowledging.
    ///
    /// WASM + `wasm-idb-persist` only.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    pub async fn with_keypair_idb(keypair: Keypair, db_name: &str) -> Result<Self, SdkError> {
        let sdk = EntitySDK::builder()
            .config(PeerConfig {
                debug_open_grants: true,
                ..PeerConfig::default()
            })
            .with_inspect_routing()
            .keypair(keypair)
            .connector(Arc::new(entity_peer::transport::BrowserWebSocketConnector))
            .idb(db_name)
            .build_async()
            .await?;
        Ok(Self {
            sdk,
            connector_override: None,
        })
    }

    fn with_keypair_and_optional_connector(
        keypair: Option<Keypair>,
        connector_override: Option<Arc<dyn entity_peer::transport::Connector>>,
    ) -> Self {
        // `mut` is conditional — only the cfg-gated WASM and native-ws
        // branches (or the override below) reassign builder.
        #[allow(unused_mut)]
        let mut builder = EntitySDK::builder()
            .config(PeerConfig {
                debug_open_grants: true,
                ..PeerConfig::default()
            })
            // Always-on inspect routing for the primary peer. Zero
            // cost when no sinks attached (the demuxer hooks early-
            // return on empty registry).
            .with_inspect_routing();

        // A caller-supplied keypair pins the primary peer-id (stable across
        // runs); otherwise generate a fresh one.
        builder = match keypair {
            Some(kp) => builder.keypair(kp),
            None => builder.generate_keypair(),
        };

        if let Some(c) = connector_override.clone() {
            builder = builder.connector(c);
        } else {
            // On WASM, use browser WebSocket connector for outbound connections.
            #[cfg(target_arch = "wasm32")]
            {
                builder = builder.connector(Arc::new(
                    entity_peer::transport::BrowserWebSocketConnector,
                ));
            }

            // On native with websocket feature, use WebSocket connector.
            #[cfg(feature = "native-ws")]
            {
                builder = builder.connector(Arc::new(
                    entity_peer::transport::WebSocketConnector,
                ));
            }
        }

        let sdk = builder.build().expect("SDK build should not fail with generated keypair");

        Self { sdk, connector_override }
    }

    /// Add peers recovered from app-tier persistent storage. Each peer is
    /// added to the SDK with `persisted: true` metadata so the UI can
    /// distinguish restored peers from session-only ones.
    ///
    /// Failures on individual peers are logged and skipped; the rest still
    /// load. Persistence I/O lives in the app layer — see the egui app's
    /// `persistence` module for the reference filesystem/localStorage
    /// implementation.
    pub fn load_persisted(&mut self, persisted: Vec<PersistedPeer>) {
        for pp in persisted.into_iter() {
            let config = PeerConfig {
                debug_open_grants: true,
                ..PeerConfig::default()
            };

            // Native + sqlite-feature: route through the sqlite-aware
            // create path when the persisted record names a DB file.
            // The `sqlite_path` field is unconditional on the struct,
            // but only honored when both gates open.
            #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
            let create_result = match pp.sqlite_path {
                Some(path) => self.sdk.create_peer_with_sqlite(
                    pp.keypair, config, self.make_connector(), path,
                ),
                None => self.sdk.create_peer(pp.keypair, config, self.make_connector()),
            };
            #[cfg(any(target_arch = "wasm32", not(feature = "sqlite")))]
            let create_result = {
                // Field intentionally ignored on WASM / non-sqlite builds.
                let _ = &pp.sqlite_path;
                self.sdk.create_peer(pp.keypair, config, self.make_connector())
            };

            match create_result {
                Ok(pid) => {
                    self.sdk.set_metadata(&pid, PeerMetadata {
                        label: pp.label,
                        persisted: true,
                        ..PeerMetadata::default()
                    });
                    tracing::info!(peer_id = %pid, "loaded persisted peer");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load persisted peer");
                }
            }
        }
    }

    /// Access the underlying EntitySDK instance.
    pub fn sdk(&self) -> &EntitySDK {
        &self.sdk
    }

    /// Mutable access to the EntitySDK (for adding peers).
    pub fn sdk_mut(&mut self) -> &mut EntitySDK {
        &mut self.sdk
    }

    /// Resolve the transport connector for peer creation. Returns the
    /// `with_connector` override when set; otherwise the platform default.
    fn make_connector(&self) -> Option<Arc<dyn entity_peer::transport::Connector>> {
        if let Some(c) = &self.connector_override {
            return Some(c.clone());
        }
        #[cfg(target_arch = "wasm32")]
        {
            Some(Arc::new(entity_peer::transport::BrowserWebSocketConnector))
        }
        #[cfg(all(not(target_arch = "wasm32"), feature = "native-ws"))]
        {
            Some(Arc::new(entity_peer::transport::WebSocketConnector))
        }
        #[cfg(all(not(target_arch = "wasm32"), not(feature = "native-ws")))]
        {
            None
        }
    }

    /// Create a new peer with a generated keypair. Returns (peer_id, seed).
    pub fn create_new_peer(&mut self, label: Option<String>) -> (String, [u8; 32]) {
        let keypair = entity_crypto::Keypair::generate();
        let seed = keypair.secret_key_bytes();
        let config = PeerConfig {
            debug_open_grants: true,
            ..PeerConfig::default()
        };
        let peer_id = self.sdk.create_peer(keypair, config, self.make_connector())
            .expect("peer creation should not fail with generated keypair");
        self.sdk.set_metadata(&peer_id, PeerMetadata {
            label,
            ..PeerMetadata::default()
        });
        (peer_id, seed)
    }

    /// Register a remote peer (protocol-only, no local PeerContext).
    /// Returns false if the peer_id already exists.
    ///
    /// Called from `app.rs::drain_pending_backend_peers`, which is
    /// `#[cfg(target_arch = "wasm32")]` (backend peers are a Tauri/WASM
    /// concept). Native builds don't exercise this path.
    #[allow(dead_code)]
    pub fn register_backend_peer(
        &mut self,
        peer_id: String,
        label: Option<String>,
        listen_addresses: Vec<String>,
    ) -> bool {
        self.sdk.register_backend_peer(peer_id, PeerMetadata {
            listen_addresses,
            label,
            ..PeerMetadata::default()
        })
    }

    /// Delete a peer by ID. Returns false if it's the default peer or doesn't exist.
    pub fn delete_peer(&mut self, peer_id: &str) -> bool {
        self.sdk.remove_peer(peer_id)
    }

    /// Update only the label of `peer_id`'s metadata, preserving
    /// other fields. See [`EntitySDK::set_peer_label`].
    pub fn set_peer_label(&mut self, peer_id: &str, label: Option<String>) {
        self.sdk.set_peer_label(peer_id, label);
    }

    /// The primary peer's ID (default for new windows).
    pub fn primary_peer_id(&self) -> &str {
        self.sdk.default_peer_id()
    }

    /// Look up a PeerContext by peer ID.
    pub fn peer_context(&self, peer_id: &str) -> Option<&PeerContext> {
        self.sdk.peer(peer_id)
    }

    /// Look up a PeerContext by peer ID, returning an owned
    /// `Arc<PeerContext>`. For consumers that need to hold the peer
    /// beyond a `&self` borrow (gdext nodes, async tasks that spawn
    /// from a synchronous resolution site). Tier 2 multi-peer-hosting
    /// path — see [`EntitySDK::peer_arc`].
    pub fn peer_context_arc(&self, peer_id: &str) -> Option<Arc<PeerContext>> {
        self.sdk.peer_arc(peer_id)
    }

    /// Look up a PeerContext by peer ID, falling back to the default peer.
    pub fn peer_context_or_default(&self, peer_id: &str) -> &PeerContext {
        self.sdk.peer(peer_id).unwrap_or_else(|| self.sdk.default_peer())
    }

    /// Direct access to a kernel Peer by ID.
    #[cfg(feature = "native-ws")]
    pub fn peer(&self, peer_id: &str) -> Option<&Peer> {
        self.sdk.peer(peer_id).map(|ctx| ctx.peer())
    }

    /// Get the shared state for a peer (created once, reused for all operations).
    pub fn peer_shared(&self, peer_id: &str) -> Option<Arc<PeerShared>> {
        self.sdk.peer(peer_id).map(|ctx| ctx.peer_shared())
    }

    /// State generation counter for DOM snapshot detection.
    #[allow(dead_code)]
    pub fn generation(&self) -> u64 {
        self.sdk.generation()
    }

    // -- Tree access (routes to correct PeerContext) --

    /// Get the entity at a full qualified path.
    pub fn get_entity(&self, peer_id: &str, path: &str) -> Option<Entity> {
        self.sdk.peer(peer_id)?.store().get(path)
    }

    /// List all entries in a peer's tree under a prefix.
    pub fn tree_listing(&self, peer_id: &str, prefix: &str) -> Vec<LocationEntry> {
        self.sdk.peer(peer_id)
            .map(|ctx| ctx.store().list(prefix))
            .unwrap_or_default()
    }

    /// Total entities in a peer's content store. Called from
    /// `dom/tree.rs` (WASM-only render path).
    #[allow(dead_code)]
    pub fn entity_count(&self, peer_id: &str) -> usize {
        self.sdk.peer(peer_id)
            .map(|ctx| ctx.entity_count())
            .unwrap_or(0)
    }

    /// Total paths in a peer's tree. Called from `dom/tree.rs` (WASM-only).
    #[allow(dead_code)]
    pub fn path_count(&self, peer_id: &str) -> usize {
        self.sdk.peer(peer_id)
            .map(|ctx| ctx.path_count())
            .unwrap_or(0)
    }

    /// Discover handler interfaces registered on a peer. Called from
    /// WASM-only `render_dom` paths (execute_console).
    #[allow(dead_code)]
    pub fn discover_handlers(&self, peer_id: &str) -> Vec<HandlerInfo> {
        self.sdk.peer(peer_id)
            .map(|ctx| ctx.discover_handlers())
            .unwrap_or_default()
    }

    /// Discover type definitions registered on a peer (SDK-OPERATIONS §9.2).
    /// Mirrors [`discover_handlers`].
    #[allow(dead_code)]
    pub fn discover_types(&self, peer_id: &str) -> Vec<TypeInfo> {
        self.sdk.peer(peer_id)
            .map(|ctx| ctx.discover_types())
            .unwrap_or_default()
    }

    /// List pending inbox entries on a peer (SDK-EXTENSION-OPERATIONS §7).
    #[allow(dead_code)]
    pub fn inbox_list(&self, peer_id: &str) -> Vec<LocationEntry> {
        self.sdk.peer(peer_id)
            .map(|ctx| ctx.inbox_list())
            .unwrap_or_default()
    }

    /// Read a specific inbox delivery by relative path (under `system/inbox/`).
    #[allow(dead_code)]
    pub fn inbox_get(&self, peer_id: &str, relative_path: &str) -> Option<Entity> {
        self.sdk.peer(peer_id)?.inbox_get(relative_path)
    }

    /// History query on a peer (SDK-EXTENSION-OPERATIONS §5).
    /// Resolves to `Err` if `peer_id` is not registered.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(dead_code)]
    pub fn history_query(
        &self,
        peer_id: &str,
        path: impl Into<String>,
        options: HistoryQueryOptions,
    ) -> impl std::future::Future<Output = Result<HistoryQueryResult, SdkError>> + Send + 'static {
        let path = path.into();
        let ctx_fut = self.sdk.peer(peer_id).map(|ctx| ctx.history_query(path, options));
        async move {
            match ctx_fut {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    pub fn history_query(
        &self,
        peer_id: &str,
        path: impl Into<String>,
        options: HistoryQueryOptions,
    ) -> impl std::future::Future<Output = Result<HistoryQueryResult, SdkError>> + 'static {
        let path = path.into();
        let ctx_fut = self.sdk.peer(peer_id).map(|ctx| ctx.history_query(path, options));
        async move {
            match ctx_fut {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    /// History rollback on a peer (SDK-EXTENSION-OPERATIONS §5).
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(dead_code)]
    pub fn history_rollback(
        &self,
        peer_id: &str,
        path: impl Into<String>,
        target_hash: Hash,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + Send + 'static {
        let path = path.into();
        let ctx_fut = self.sdk.peer(peer_id).map(|ctx| ctx.history_rollback(path, target_hash));
        async move {
            match ctx_fut {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    pub fn history_rollback(
        &self,
        peer_id: &str,
        path: impl Into<String>,
        target_hash: Hash,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + 'static {
        let path = path.into();
        let ctx_fut = self.sdk.peer(peer_id).map(|ctx| ctx.history_rollback(path, target_hash));
        async move {
            match ctx_fut {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    /// List active subscriptions on a peer (SDK-EXTENSION-OPERATIONS §3).
    #[allow(dead_code)]
    pub fn list_subscriptions(&self, peer_id: &str) -> Vec<SubscriptionInfo> {
        self.sdk.peer(peer_id)
            .map(|ctx| ctx.list_subscriptions())
            .unwrap_or_default()
    }

    /// Explicit unsubscribe by id on a peer.
    /// Resolves to `Err(SdkError::HandlerError)` if `peer_id` is unknown.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(dead_code)]
    pub fn unsubscribe(
        &self,
        peer_id: &str,
        subscription_id: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + Send + 'static {
        let id = subscription_id.into();
        let ctx_unsub = self.sdk.peer(peer_id).map(|ctx| ctx.unsubscribe(id));
        async move {
            match ctx_unsub {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    pub fn unsubscribe(
        &self,
        peer_id: &str,
        subscription_id: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + 'static {
        let id = subscription_id.into();
        let ctx_unsub = self.sdk.peer(peer_id).map(|ctx| ctx.unsubscribe(id));
        async move {
            match ctx_unsub {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    /// Run an L1 query on a peer (SDK-OPERATIONS §5.1).
    ///
    /// Returns an owning future. Resolves to `Err(SdkError::HandlerError)`
    /// if `peer_id` is not registered.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(dead_code)]
    pub fn query(
        &self,
        peer_id: &str,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<QueryResults, SdkError>> + Send + 'static {
        let ctx_query = self.sdk.peer(peer_id).map(|ctx| ctx.query(expression));
        async move {
            match ctx_query {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    pub fn query(
        &self,
        peer_id: &str,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<QueryResults, SdkError>> + 'static {
        let ctx_query = self.sdk.peer(peer_id).map(|ctx| ctx.query(expression));
        async move {
            match ctx_query {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    /// Run an L1 count on a peer (SDK-EXTENSION-OPERATIONS §6).
    ///
    /// Returns an owning future. Resolves to `Err(SdkError::HandlerError)`
    /// if `peer_id` is not registered.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(dead_code)]
    pub fn count(
        &self,
        peer_id: &str,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<u64, SdkError>> + Send + 'static {
        let ctx_count = self.sdk.peer(peer_id).map(|ctx| ctx.count(expression));
        async move {
            match ctx_count {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    pub fn count(
        &self,
        peer_id: &str,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<u64, SdkError>> + 'static {
        let ctx_count = self.sdk.peer(peer_id).map(|ctx| ctx.count(expression));
        async move {
            match ctx_count {
                Some(fut) => fut.await,
                None => Err(SdkError::HandlerError("unknown peer_id".into())),
            }
        }
    }

    /// Store an entity at a full qualified path (L0 direct).
    ///
    /// Prefer [`dispatch_write`](Self::dispatch_write) for state mutations —
    /// this stays available for bootstrapping and tests.
    #[allow(dead_code)]
    pub fn put_entity(&self, peer_id: &str, path: &str, entity: Entity) -> Option<Hash> {
        self.sdk.peer(peer_id)?.store().put(path, entity).ok()
    }

    /// Dispatch a state write via L1 (async, capability-checked), fire-and-forget.
    ///
    /// Spawns `ctx.put(path, entity).await` on the available runtime
    /// (tokio on native, spawn_local on WASM). The caller does not await.
    /// On completion the tree mutation increments the generation counter,
    /// so the next frame sees the new state via the normal snapshot path.
    ///
    /// This is what views should use for state mutations from `handle_action`.
    /// It routes writes through the `system/tree` handler, emitting evidence
    /// and (once grants are enforced) honoring capability checks.
    ///
    /// Errors are logged to tracing; there is no return value because the
    /// tree is the single source of truth — if the write fails, the UI
    /// simply keeps showing the old state on the next render. Apps that
    /// want UI feedback on write failures should use `ctx.put().await`
    /// directly and surface the error themselves.
    pub fn dispatch_write(&self, peer_id: &str, path: impl Into<String>, entity: Entity) {
        let Some(ctx) = self.sdk.peer(peer_id) else {
            tracing::warn!(peer_id = %peer_id, "dispatch_write: no PeerContext for peer");
            return;
        };
        let path: String = path.into();
        let peer_id_owned = peer_id.to_string();
        let put_future = ctx.put(path.clone(), entity);

        let task = async move {
            match put_future.await {
                Ok(_hash) => {
                    tracing::trace!(peer_id = %peer_id_owned, path = %path, "dispatch_write: put ok");
                }
                Err(e) => {
                    tracing::warn!(peer_id = %peer_id_owned, path = %path, error = %e, "dispatch_write: put failed");
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(task);
            } else {
                tracing::error!("dispatch_write: no tokio runtime active; write dropped");
            }
        }
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_ecf::{text, to_ecf};

    fn make_entity(entity_type: &str, content: &str) -> Entity {
        let data = to_ecf(&text(content));
        Entity::new(entity_type, data).unwrap()
    }

    #[test]
    fn new_creates_primary_peer() {
        let pm = PeerManager::new();
        assert!(!pm.primary_peer_id().is_empty());
        // Use `peer_context` (always available) rather than `peer` (which is
        // `#[cfg(feature = "native-ws")]`) so the test runs in every feature
        // configuration of entity-sdk.
        assert!(pm.peer_context(pm.primary_peer_id()).is_some());
    }

    #[test]
    fn get_entity_returns_bootstrapped_system_tree() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        let path = format!("/{}/system/tree", pid);
        let entity = pm.get_entity(pid, &path);
        assert!(entity.is_some(), "system/tree handler should be bootstrapped");
    }

    #[test]
    fn tree_listing_returns_qualified_paths() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id().to_string();
        let path = format!("/{}/docs/readme", pid);
        pm.put_entity(&pid, &path, make_entity("test/t", "hello"));
        let entries = pm.tree_listing(&pid, &format!("/{}/docs/", pid));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, format!("/{}/docs/readme", pid));
    }

    #[test]
    fn tree_listing_includes_system_paths() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        let prefix = format!("/{}/system/", pid);
        let entries = pm.tree_listing(pid, &prefix);
        assert!(!entries.is_empty(), "should have bootstrapped system entries");
    }

    #[test]
    fn get_entity_missing_returns_none() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        assert!(pm.get_entity(pid, "nonexistent/path").is_none());
    }

    #[test]
    fn entity_count_includes_bootstrap() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        assert!(pm.entity_count(pid) > 0);
    }

    #[test]
    fn generation_starts_at_zero() {
        let pm = PeerManager::new();
        assert_eq!(pm.generation(), 0);
    }

    #[test]
    fn put_entity_increments_generation() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id().to_string();
        let p1 = format!("/{}/test/a", pid);
        let p2 = format!("/{}/test/b", pid);
        pm.put_entity(&pid, &p1, make_entity("t", "1"));
        assert_eq!(pm.generation(), 1);
        pm.put_entity(&pid, &p2, make_entity("t", "2"));
        assert_eq!(pm.generation(), 2);
    }

    #[test]
    fn unknown_peer_returns_none() {
        let pm = PeerManager::new();
        // Unknown peer_id routes to no PeerContext, returns None.
        assert!(pm.get_entity("any_peer", "nonexistent/path").is_none());
    }

    #[test]
    fn tree_listing_from_root_shows_peer_namespace() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        let prefix = format!("/{}", pid);
        let entries = pm.tree_listing(pid, "");
        assert!(!entries.is_empty());
        for entry in &entries {
            assert!(entry.path.starts_with(&prefix), "path {} should start with /{}", entry.path, pid);
        }
    }

    #[test]
    fn discover_handlers_finds_bootstrapped() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        let handlers = pm.discover_handlers(pid);
        assert!(!handlers.is_empty(), "should discover bootstrapped handlers");

        let tree_handler = handlers.iter().find(|h| h.pattern == "system/tree");
        assert!(tree_handler.is_some(), "system/tree handler should be discovered");

        let tree = tree_handler.unwrap();
        assert!(!tree.name.is_empty());
        assert!(!tree.operations.is_empty(), "system/tree should have operations");
    }

    #[test]
    fn discover_handlers_sorted_by_pattern() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        let handlers = pm.discover_handlers(pid);
        for pair in handlers.windows(2) {
            assert!(pair[0].pattern <= pair[1].pattern, "handlers should be sorted");
        }
    }

    #[test]
    fn discover_types_finds_bootstrapped() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        let types = pm.discover_types(pid);
        assert!(!types.is_empty(), "should discover bootstrapped type definitions");
    }

    #[test]
    fn discover_types_sorted_by_type_path() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        let types = pm.discover_types(pid);
        for pair in types.windows(2) {
            assert!(pair[0].type_path <= pair[1].type_path, "types should be sorted");
        }
    }

    #[test]
    fn discover_types_unknown_peer_returns_empty() {
        let pm = PeerManager::new();
        let types = pm.discover_types("nonexistent-peer-id");
        assert!(types.is_empty());
    }

    #[test]
    fn inbox_list_unknown_peer_returns_empty() {
        let pm = PeerManager::new();
        assert!(pm.inbox_list("nonexistent-peer-id").is_empty());
    }

    #[test]
    fn list_subscriptions_empty_for_fresh_peer() {
        let pm = PeerManager::new();
        assert!(pm.list_subscriptions(pm.primary_peer_id()).is_empty());
    }

    #[test]
    fn list_subscriptions_unknown_peer_returns_empty() {
        let pm = PeerManager::new();
        assert!(pm.list_subscriptions("nonexistent-peer-id").is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn history_query_routes_to_peer() {
        use entity_ecf::{bool_val, text, to_ecf, Value};
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id().to_string();
        let path = format!("/{}/app/test/h", pid);
        let ctx = pm.peer_context(&pid).expect("primary peer context");

        // Enable history recording for paths matching the test prefix.
        let cfg_path = format!("/{}/system/history/config/test-cfg", pid);
        let cfg = Entity::new(
            "system/history/config",
            to_ecf(&Value::Map(vec![
                (text("enabled"), bool_val(true)),
                (text("pattern"), text(&format!("/{}/app/test/*", pid))),
            ])),
        ).unwrap();
        ctx.store().put(&cfg_path, cfg).unwrap();

        // L1 put through emit pathway so the history engine records.
        ctx.put(&path, Entity::new("test/v", to_ecf(&text("a"))).unwrap()).await.unwrap();
        ctx.put(&path, Entity::new("test/v", to_ecf(&text("b"))).unwrap()).await.unwrap();

        let result = pm.history_query(&pid, &path, HistoryQueryOptions::default()).await.expect("history query should succeed");
        assert_eq!(result.path, path);
        assert!(result.transitions.len() >= 2, "got {} transitions", result.transitions.len());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn history_unknown_peer_errors() {
        let pm = PeerManager::new();
        let result = pm.history_query("nonexistent-peer-id", "/whatever", HistoryQueryOptions::default()).await;
        assert!(result.is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn unsubscribe_unknown_peer_errors() {
        let pm = PeerManager::new();
        assert!(pm.unsubscribe("nonexistent-peer-id", "sub-id").await.is_err());
    }

    #[test]
    fn inbox_routes_to_peer() {
        use entity_ecf::{text, to_ecf};
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id().to_string();
        let path = format!("/{}/system/inbox/sub-1/note", pid);
        pm.put_entity(
            &pid,
            &path,
            Entity::new("test/note", to_ecf(&text("hi"))).unwrap(),
        ).expect("seed put");

        let entries = pm.inbox_list(&pid);
        assert!(entries.iter().any(|e| e.path == path));

        let got = pm.inbox_get(&pid, "sub-1/note").expect("get should resolve");
        assert_eq!(got.entity_type, "test/note");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn query_routes_to_peer() {
        use entity_ecf::{text, to_ecf, Value};
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id().to_string();

        let target = format!("/{}/app/test/article", pid);
        pm.put_entity(
            &pid,
            &target,
            Entity::new("test/article", to_ecf(&text("hi"))).unwrap(),
        ).expect("put should succeed");

        let expr = Entity::new(
            "system/query/expression",
            to_ecf(&Value::Map(vec![(text("type_filter"), text("test/article"))])),
        ).unwrap();
        let results = pm.query(&pid, expr).await.expect("query should succeed");
        assert!(
            results.matches.iter().any(|m| m.path == target),
            "PeerManager::query should route to peer and return matches"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn count_routes_to_peer() {
        use entity_ecf::{text, to_ecf, Value};
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id().to_string();

        for i in 0..2 {
            pm.put_entity(
                &pid,
                &format!("/{}/app/test/widget-{}", pid, i),
                Entity::new("test/widget", to_ecf(&text("x"))).unwrap(),
            ).expect("put should succeed");
        }

        let expr = Entity::new(
            "system/query/expression",
            to_ecf(&Value::Map(vec![(text("type_filter"), text("test/widget"))])),
        ).unwrap();
        let n = pm.count(&pid, expr).await.expect("count should succeed");
        assert_eq!(n, 2);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn count_unknown_peer_errors() {
        use entity_ecf::{text, to_ecf, Value};
        let pm = PeerManager::new();
        let expr = Entity::new(
            "system/query/expression",
            to_ecf(&Value::Map(vec![(text("type_filter"), text("anything"))])),
        ).unwrap();
        assert!(pm.count("nonexistent-peer-id", expr).await.is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn query_unknown_peer_errors() {
        use entity_ecf::{text, to_ecf, Value};
        let pm = PeerManager::new();
        let expr = Entity::new(
            "system/query/expression",
            to_ecf(&Value::Map(vec![(text("type_filter"), text("anything"))])),
        ).unwrap();
        let result = pm.query("nonexistent-peer-id", expr).await;
        assert!(result.is_err(), "unknown peer should yield Err");
    }

    #[test]
    fn two_peer_routing_isolates_state() {
        let mut pm = PeerManager::new();
        let pid1 = pm.primary_peer_id().to_string();

        // Add a second peer.
        let kp2 = entity_crypto::Keypair::generate();
        let pid2 = pm.sdk_mut().create_peer(
            kp2,
            entity_peer::PeerConfig::default(),
            None,
        ).unwrap();

        // Write to peer1's tree.
        let path1 = format!("/{}/test/data", pid1);
        pm.put_entity(&pid1, &path1, make_entity("t", "from-peer1"));
        assert!(pm.get_entity(&pid1, &path1).is_some());

        // Peer2 should NOT see peer1's data.
        assert!(pm.get_entity(&pid2, &path1).is_none());

        // Write to peer2's tree.
        let path2 = format!("/{}/test/data", pid2);
        pm.put_entity(&pid2, &path2, make_entity("t", "from-peer2"));
        assert!(pm.get_entity(&pid2, &path2).is_some());
        assert!(pm.get_entity(&pid1, &path2).is_none());
    }

    #[test]
    fn peer_context_or_default_fallback() {
        let pm = PeerManager::new();
        let pid = pm.primary_peer_id();
        // Valid peer_id returns that peer.
        let ctx = pm.peer_context_or_default(pid);
        assert_eq!(ctx.peer_id(), pid);
        // Invalid peer_id falls back to default.
        let ctx2 = pm.peer_context_or_default("nonexistent");
        assert_eq!(ctx2.peer_id(), pid);
    }
}
