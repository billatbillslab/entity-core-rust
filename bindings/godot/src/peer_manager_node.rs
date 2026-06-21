//! EntityPeerManager — Godot Node that hosts N peers in one process.
//!
//! Each spawned
//! peer is an independent `EntityPeer` child node with its own tokio
//! runtime (today's EntityPeer model — unchanged). The manager is a
//! Node-tree organizer + peer_id-keyed lookup table.
//!
//! Native-only — relies on `EntityPeer::boot` (persistence-backed) and
//! `EntityPeer::start` (deterministic seed), both of which gate the
//! native path. WASM hosting goes through the wasm-worker crates;
//! a worker-side counterpart can land later if a driver materializes.
//!
//! ## Inline corrections vs the original request
//!
//! `REQUEST-BINDING-TIER-2-MULTI-PEER §2` proposed three
//! `identity_source` values:
//!   - `"new_keypair"` — supported.
//!   - `"import_bundle"` — NOT supported in v1. Requires an
//!     `IdentityBundle` (PEM bytes + identity entity) input the
//!     Dictionary doesn't carry. Returns null with an error log.
//!     Follow-up: `spawn_peer_from_bundle(bundle_bytes, alias, ...)`.
//!   - `"restore_from_quorum"` — NOT supported in v1. Requires a
//!     quorum hash + recovery proof not in the Dictionary. Follow-up:
//!     `spawn_peer_from_quorum_recovery(quorum_hash, alias, ...)`.
//!
//! `extensions` field is accepted but treated as opaque metadata in
//! v1 — Cargo features are compile-time at the SDK layer (see Phase C
//! `installed_extensions`), so per-peer subsetting is a Tier-3+ future
//! shape. Any non-`"all"` value warns once.
//!
//! `storage_kind` accepts `"sqlite"` or `"memory"`. `":memory:"` is
//! NOT supported (per the Phase C decision — no builder method
//! produces it). Other values return null with an error log.

use std::collections::BTreeMap;
use std::sync::Arc;

use entity_peer::transport::{MemoryConnector, MemoryTransportRegistry};
use entity_sdk::{EntitySDK, PeerMetadata};
use godot::prelude::*;

use crate::peer_node::EntityPeer;

/// Multi-peer host. Spawns + tracks `EntityPeer` children by peer_id.
///
/// ## Architecture (T4-infra restructure)
///
/// The manager is the Godot binding's consumer-tier equivalent of
/// `entitysdk::PeerManager`. It owns:
///
/// 1. **One shared `tokio::runtime::Runtime`** (`self.runtime`) —
///    constructed at `init`. Each spawned peer borrows a `Handle` clone
///    via `EntityPeer::inject_runtime_handle` before `start()`/`boot()`.
///    Replaces the per-peer-runtime model from Tier 2 multi-peer
///    hosting. Peer isolation is at the state layer (`Arc<PeerContext>`
///    per peer — independent tree / identity / capabilities /
///    dispatcher), not the runtime layer.
///
/// 2. **One `entity_sdk::EntitySDK`** (`self.sdk`) — the centralized
///    peer registry + `PeerMetadata` storage. After `EntityPeer` builds
///    its `PeerContext` (via `build_start_context` / `build_boot_context`,
///    keeping the existing inspectability-hook pre-build install path),
///    the manager hands it to `sdk.insert_peer_with_metadata` and fetches
///    the registered `Arc<PeerContext>` back via `peer_arc`. The Arc is
///    then handed to `EntityPeer::spin_up_arc` for runtime wiring.
///    Adopts the `insert_peer` surface Dom shipped for SDK/peer
///    container coherence.
///
/// 3. **`primary_peer_id: Option<String>`** — the first user-spawned
///    peer's id. The `EntitySDK` has its own `default_peer_id` (a
///    phantom primary auto-constructed by `EntitySDK::builder()` —
///    design friction noted in §4 of the SDK request doc), but we
///    track our own primary so that what the user sees as "primary"
///    matches what they spawned, not the throwaway SDK builder peer.
///
/// 4. **`peers: BTreeMap<peer_id, Gd<EntityPeer>>`** — the Godot Node
///    registry. EntityPeer Godot Nodes are children of the manager so
///    their `_process` runs; the manager holds strong refs that get
///    dropped on `remove_peer`. The SDK and this registry both hold
///    references to the same `Arc<PeerContext>`; removing a peer
///    requires dropping both (`sdk.remove_peer` + dropping the
///    `Gd<EntityPeer>`).
///
/// Direct `EntityPeer` instantiation (test scaffolding that doesn't go
/// through `spawn_peer`) keeps working — `EntityPeer::start()` builds
/// + wraps its own `Arc` without SDK involvement (`peer_node.rs`
/// `RuntimeRef::Owned` path also takes over when no handle has been
/// injected). The SDK-mediated path is `spawn_peer`-only.
///
/// Rationale + alternatives considered: see the T4-infra restructure
/// plan.
#[derive(GodotClass)]
#[class(base = Node)]
pub struct EntityPeerManager {
    base: Base<Node>,
    /// Peer_id → EntityPeer Gd handle. Strong refs; dropped on
    /// `remove_peer` (which also queues_free the underlying node).
    peers: BTreeMap<String, Gd<EntityPeer>>,
    /// Shared tokio runtime — one across all hosted peers. Constructed
    /// in `init`; lives until the manager is freed. Each peer borrows
    /// a `Handle` clone via `EntityPeer::inject_runtime_handle` at
    /// `spawn_peer` time.
    ///
    /// `Arc` so the runtime can move-or-clone across helpers if the
    /// manager grows multiple internal owners later (T4-infra +
    /// MemoryConnector follow-up wants the registry held alongside).
    runtime: Arc<tokio::runtime::Runtime>,
    /// Centralized peer registry + metadata. Owns `Arc<PeerContext>` for
    /// every spawned peer (handed in via `insert_peer_with_metadata`
    /// during `spawn_peer`; cleaned up via `remove_peer` during this
    /// struct's `remove_peer`). The SDK was constructed with a phantom
    /// primary peer (see `init`); that peer is not user-visible and we
    /// override its `default_peer_id` semantics with our own
    /// `primary_peer_id` field.
    sdk: EntitySDK,
    /// First user-spawned peer's id (T3.0.f surface). Distinct from
    /// `sdk.default_peer_id()` which points at the phantom primary. Set
    /// on the first successful `spawn_peer`; remains until that peer is
    /// removed via `remove_peer`, at which point we promote the next
    /// user peer (sorted-id order) or clear if none remain.
    primary_peer_id: Option<String>,
    /// Shared `MemoryTransportRegistry` for the manager. Constructed at
    /// `init` (fresh per-manager registry — NOT `process_global()` —
    /// so multiple managers in the same process don't cross-bind, and
    /// test isolation holds). Memory-transport peers (those with
    /// `listen_address` starting with `memory://`) get a clone of this
    /// registry injected via `EntityPeer::inject_memory_registry` so
    /// their `MemoryListener::bind` registers here. TCP peers leave
    /// the registry untouched.
    memory_registry: Arc<MemoryTransportRegistry>,
    /// Shared `MemoryConnector` derived from `memory_registry`. Wrapped
    /// in `Arc<dyn Connector>` for injection into peers'
    /// `PeerContextBuilder::connector(...)` via
    /// `EntityPeer::inject_connector`. Only injected for memory-transport
    /// peers; TCP peers use the platform-default connector instead.
    memory_connector: Arc<dyn entity_peer::transport::Connector>,
}

#[godot_api]
impl INode for EntityPeerManager {
    fn init(base: Base<Node>) -> Self {
        // Construct the shared runtime up front. If this fails the
        // manager is unusable — there's nothing to fall back to (we
        // can't even spawn peers). tokio runtime creation failure is
        // system-resource-exhaustion territory and not recoverable.
        let runtime = tokio::runtime::Runtime::new()
            .expect("EntityPeerManager: failed to construct shared tokio runtime");
        // Construct the SDK with a generated-keypair "phantom" primary
        // peer. The SDK builder requires a keypair → primary peer to
        // produce an SDK; we don't expose this peer through the Godot
        // surface (`list_peers`, `peer_count`, etc. iterate
        // `self.peers`, not `self.sdk.list_peer_ids`). The phantom is
        // ~one PeerContext worth of memory and stays unreachable from
        // user code. Design friction noted around SDK/peer container
        // coherence — open question whether SDK should grow a `new_empty()`
        // constructor; not blocking this restructure.
        let sdk = EntitySDK::builder()
            .generate_keypair()
            .build()
            .expect("EntityPeerManager: SDK build (phantom primary peer) should not fail");
        // Fresh registry per manager (NOT process_global()) so multiple
        // managers in the same process — e.g., a primary and a test
        // harness — don't share listener bindings. MemoryConnector
        // wraps this same registry so a manager's outbound and inbound
        // memory traffic resolve against the same listener table.
        let memory_registry = MemoryTransportRegistry::new();
        let memory_connector: Arc<dyn entity_peer::transport::Connector> =
            Arc::new(MemoryConnector::new(memory_registry.clone()));
        Self {
            base,
            peers: BTreeMap::new(),
            runtime: Arc::new(runtime),
            sdk,
            primary_peer_id: None,
            memory_registry,
            memory_connector,
        }
    }
}

#[godot_api]
impl EntityPeerManager {
    /// Spawn a new peer with the given Config Dictionary.
    ///
    /// Dictionary keys (per `REQUEST-BINDING-TIER-2-MULTI-PEER §2`):
    /// - `identity_source`: `"new_keypair"` only (v1).
    /// - `alias`: peer label (also used as `peer_name` for SQLite
    ///   persistence directory).
    /// - `storage_kind`: `"sqlite"` | `"memory"`.
    /// - `storage_path`: data-dir override (SQLite only; empty →
    ///   platform default).
    /// - `listen_address`: TCP `"host:port"` (empty → no listener).
    /// - `extensions`: accepted, ignored in v1 (warns on non-empty
    ///   non-`"all"` values).
    /// - `composition_role`: app-layer metadata, no kernel effect in v1.
    ///
    /// Returns the spawned `EntityPeer` `Gd` handle on success, `null`
    /// on validation or build failure. The peer is added as a child
    /// of this manager so its `_process` runs.
    #[func]
    fn spawn_peer(&mut self, config: Dictionary) -> Variant {
        let identity_source = dict_get_string(&config, "identity_source")
            .unwrap_or_else(|| "new_keypair".to_string());
        if identity_source != "new_keypair" {
            godot_error!(
                "EntityPeerManager.spawn_peer: identity_source = {:?} not supported in v1. \
                 Use 'new_keypair'. Bundle/quorum restoration follow-ups: \
                 spawn_peer_from_bundle / spawn_peer_from_quorum_recovery.",
                identity_source
            );
            return Variant::nil();
        }

        let alias = dict_get_string(&config, "alias").unwrap_or_default();
        let storage_kind = dict_get_string(&config, "storage_kind")
            .unwrap_or_else(|| "memory".to_string());
        let storage_path = dict_get_string(&config, "storage_path").unwrap_or_default();
        let listen_address = dict_get_string(&config, "listen_address").unwrap_or_default();
        let extensions_field = dict_get_string(&config, "extensions").unwrap_or_default();
        // `debug_open_grants` config field. When true, the kernel loosens
        // capability-chain attenuation checks (handler dispatch + cap-mint
        // accept overscoped child caps). Used by integration tests
        // exercising cross-peer dispatch without going through a full
        // grant-shaping flow. Default false (strict). Read as bool from
        // the Dictionary; missing/non-bool → false.
        let debug_grants: bool = config
            .get(GString::from("debug_grants").to_variant())
            .and_then(|v| v.try_to::<bool>().ok())
            .unwrap_or(false);

        if !extensions_field.is_empty() && extensions_field != "all" {
            godot_warn!(
                "EntityPeerManager.spawn_peer: extensions = {:?} accepted but ignored — \
                 per-peer extension subsetting is not implemented (Cargo features are \
                 compile-time per Phase C installed_extensions). Treating as 'all'.",
                extensions_field
            );
        }

        // Validate storage_kind. ":memory:" is intentionally NOT accepted
        // — Phase C storage_kind dropped it from the canonical set
        // because no PeerContextBuilder method exposes it.
        if storage_kind != "sqlite" && storage_kind != "memory" {
            godot_error!(
                "EntityPeerManager.spawn_peer: storage_kind = {:?} invalid. \
                 Expected 'sqlite' or 'memory'.",
                storage_kind
            );
            return Variant::nil();
        }

        // SQLite path needs a non-empty alias (used as peer_name → data
        // dir name).
        if storage_kind == "sqlite" && alias.is_empty() {
            godot_error!(
                "EntityPeerManager.spawn_peer: alias is required for storage_kind='sqlite' \
                 (it names the persistence directory)."
            );
            return Variant::nil();
        }

        // Build the EntityPeer Gd<>. NodeClass::init is no-arg; we set
        // properties before adding-as-child + calling start/boot.
        let mut peer_gd = EntityPeer::new_alloc();

        // Name the node (used in the Godot scene tree). Defaults to a
        // stable per-peer string so duplicate-add panics surface as
        // godot-side name collisions rather than silent overwrites.
        let node_name = if alias.is_empty() {
            format!("peer-{}", self.peers.len() + 1)
        } else {
            format!("peer-{}", alias)
        };
        peer_gd.set_name(&node_name);

        // Listen address (always set; empty string means EntityPeer
        // skips the listener — see peer_node.rs listen() error path).
        peer_gd.set("listen_address", &GString::from(listen_address.as_str()).to_variant());
        // Pass debug_grants through to the EntityPeer so build_*_context
        // bakes it into PeerConfig.debug_open_grants.
        peer_gd.set("debug_grants", &debug_grants.to_variant());

        // Inject the shared runtime handle BEFORE building the
        // PeerContext or spinning up — the peer captures it during
        // spin_up_arc rather than constructing a per-peer Runtime.
        let handle_for_peer = self.runtime.handle().clone();
        peer_gd.bind_mut().inject_runtime_handle(handle_for_peer);

        // Memory-transport peers (listen_address starting with
        // `memory://`) get the manager's MemoryConnector + registry
        // injected. TCP peers leave these unset and the builder uses
        // the platform-default connector (TcpConnector on native).
        // Connector goes into the builder (outbound); registry feeds
        // `MemoryListener::bind` inside spin_up_arc (inbound).
        let is_memory_peer = listen_address.starts_with("memory://");
        if is_memory_peer {
            peer_gd
                .bind_mut()
                .inject_connector(self.memory_connector.clone());
            peer_gd
                .bind_mut()
                .inject_memory_registry(self.memory_registry.clone());
        }

        // Storage selection: SQLite uses boot context (peer_name + data_dir),
        // memory uses start context (seed-driven, in-memory). Both go
        // through the SDK-mediated path below — build PeerContext →
        // insert_peer_with_metadata → fetch peer_arc → spin_up_arc.
        let ctx_opt = match storage_kind.as_str() {
            "memory" => {
                // Fresh random keypair → seed bytes → build_start_context.
                let kp = entity_crypto::Keypair::generate();
                let seed = kp.secret_key_bytes();
                let mut seed_pba = PackedByteArray::new();
                seed_pba.extend(seed.iter().copied());
                peer_gd.set("seed", &seed_pba.to_variant());

                self.base_mut().add_child(&peer_gd);
                peer_gd.bind_mut().build_start_context()
            }
            "sqlite" => {
                peer_gd.set("peer_name", &GString::from(alias.as_str()).to_variant());
                if !storage_path.is_empty() {
                    peer_gd.set("data_dir", &GString::from(storage_path.as_str()).to_variant());
                }
                self.base_mut().add_child(&peer_gd);
                peer_gd.bind_mut().build_boot_context()
            }
            _ => unreachable!(),
        };
        let ctx = match ctx_opt {
            Some(c) => c,
            None => {
                // build_start_context / build_boot_context already logged
                // the specific failure; just clean up here.
                peer_gd.queue_free();
                return Variant::nil();
            }
        };

        // Snapshot the peer_id before consuming `ctx` into the SDK.
        let candidate_pid = ctx.peer_id().to_string();
        if self.peers.contains_key(&candidate_pid) {
            godot_error!(
                "EntityPeerManager.spawn_peer: peer_id {} already hosted. \
                 Refusing duplicate; freeing new node.",
                candidate_pid
            );
            peer_gd.queue_free();
            return Variant::nil();
        }

        // Insert into the SDK with caller-supplied metadata (label from
        // alias, persisted flag derived from storage_kind, listen
        // addresses from config). The SDK takes ownership of `ctx` and
        // hands back an Arc<PeerContext> we can share with EntityPeer.
        let metadata = PeerMetadata {
            label: if alias.is_empty() { None } else { Some(alias.clone()) },
            persisted: storage_kind == "sqlite",
            listen_addresses: if listen_address.is_empty() {
                Vec::new()
            } else {
                vec![listen_address.clone()]
            },
        };
        let pid = match self.sdk.insert_peer_with_metadata(ctx, metadata) {
            Ok(id) => id,
            Err(e) => {
                godot_error!(
                    "EntityPeerManager.spawn_peer: SDK insert_peer failed: {}",
                    e
                );
                peer_gd.queue_free();
                return Variant::nil();
            }
        };

        // Fetch the registered Arc<PeerContext> and hand it to the peer
        // for runtime wiring. `peer_arc` is infallible here because we
        // just inserted; the `.expect` documents the invariant.
        let ctx_arc = self
            .sdk
            .peer_arc(&pid)
            .expect("peer_arc returns Some immediately after insert_peer success");
        peer_gd.bind_mut().spin_up_arc(ctx_arc);

        // First user-spawned peer becomes our primary (overriding the
        // SDK's `default_peer_id` which points at the phantom).
        if self.primary_peer_id.is_none() {
            self.primary_peer_id = Some(pid.clone());
        }

        self.peers.insert(pid, peer_gd.clone());
        peer_gd.to_variant()
    }

    /// Look up a hosted peer by ID. Returns `null` if not hosted by
    /// this manager.
    #[func]
    fn peer(&self, peer_id: GString) -> Variant {
        match self.peers.get(&peer_id.to_string()) {
            Some(gd) => gd.clone().to_variant(),
            None => Variant::nil(),
        }
    }

    /// All peer_ids hosted by this manager. Sorted (BTreeMap keys).
    #[func]
    fn list_peers(&self) -> PackedStringArray {
        let mut out = PackedStringArray::new();
        for pid in self.peers.keys() {
            out.push(&GString::from(pid.as_str()));
        }
        out
    }

    /// Remove a peer by ID. Drops the strong ref and queues its node
    /// for free. Returns `true` if a peer was removed, `false` if
    /// `peer_id` wasn't hosted.
    ///
    /// The manager does NOT enforce a "can't delete primary" rule —
    /// the manager-tier doesn't have a notion of primary. App-tier UX
    /// (e.g., `peer_display::is_user_deletable`) gates that policy.
    #[func]
    fn remove_peer(&mut self, peer_id: GString) -> bool {
        let pid = peer_id.to_string();
        match self.peers.remove(&pid) {
            Some(mut gd) => {
                // Best-effort stop before freeing — the EntityPeer's
                // stop() handles pending-future cleanup so awaiting
                // GDScript coroutines don't hang.
                gd.call("stop", &[]);
                gd.queue_free();
                // Drop the SDK's Arc<PeerContext> too. `sdk.remove_peer`
                // returns false for the phantom default peer (and we'd
                // never call this on the phantom because it's not in
                // self.peers), so a `false` here on a peer we just
                // removed from `self.peers` would be a real surprise.
                let sdk_removed = self.sdk.remove_peer(&pid);
                if !sdk_removed {
                    godot_warn!(
                        "EntityPeerManager.remove_peer: SDK refused to drop peer_id {} \
                         (was present in self.peers — possible registry drift).",
                        pid
                    );
                }
                // Promote next user peer to primary if we just removed
                // the current primary. Sorted-id order (BTreeMap keys
                // are sorted) gives deterministic promotion.
                if self.primary_peer_id.as_deref() == Some(pid.as_str()) {
                    self.primary_peer_id = self.peers.keys().next().cloned();
                }
                true
            }
            None => false,
        }
    }

    /// How many peers this manager is currently hosting.
    #[func]
    fn peer_count(&self) -> i64 {
        self.peers.len() as i64
    }

    /// The first user-spawned peer's id (T3.0.f surface). Returns the
    /// empty string when no peer has been spawned yet. Distinct from
    /// the SDK's `default_peer_id`, which points at the phantom primary
    /// auto-constructed at `init` and which is not user-visible.
    ///
    /// On `remove_peer` of the current primary, promotes the next user
    /// peer in sorted-id order; clears when no peers remain.
    #[func]
    fn primary_peer_id(&self) -> GString {
        match &self.primary_peer_id {
            Some(pid) => GString::from(pid.as_str()),
            None => GString::new(),
        }
    }

    /// Snapshot of an SDK-tracked peer's metadata as a Godot Dictionary
    /// (T3.0.e surface). Keys:
    /// - `"label"`: `String` — user-facing display label, or `""` if unset
    /// - `"persisted"`: `bool` — whether the peer's keypair is on disk
    ///   (true for sqlite-storage peers, false for memory-storage)
    /// - `"listen_addresses"`: `PackedStringArray` — every wire address
    ///   the peer accepts inbound connections on
    ///
    /// Returns an empty Dictionary for unknown peer_ids (and for the
    /// SDK's phantom primary, which the manager intentionally treats as
    /// not-a-real-peer for the Godot surface).
    #[func]
    fn peer_metadata(&self, peer_id: GString) -> Dictionary {
        let pid = peer_id.to_string();
        let mut out = Dictionary::new();
        // Filter out the SDK phantom: only peers we have a Godot
        // EntityPeer for are user-visible.
        if !self.peers.contains_key(&pid) {
            return out;
        }
        let Some(meta) = self.sdk.peer_metadata(&pid) else {
            return out;
        };
        let label_str: String = meta.label.clone().unwrap_or_default();
        out.set(
            GString::from("label"),
            GString::from(label_str.as_str()),
        );
        out.set(GString::from("persisted"), meta.persisted);
        let mut addrs = PackedStringArray::new();
        for a in &meta.listen_addresses {
            addrs.push(&GString::from(a.as_str()));
        }
        out.set(GString::from("listen_addresses"), addrs);
        out
    }
}

/// Helper: pull a String value from a Godot Dictionary by string key.
/// Returns `None` if the key is missing or the value isn't a String.
fn dict_get_string(dict: &Dictionary, key: &str) -> Option<String> {
    let v = dict.get(GString::from(key).to_variant())?;
    v.try_to::<GString>().ok().map(|g| g.to_string())
}
