//! entity-sdk — application SDK for entity-core-rust.
//!
//! This crate is the Rust-native consumption surface for entity-core. It
//! wraps the kernel (`entity-peer` and friends) with `EntitySDK` /
//! `PeerContext` and a small set of helpers for handler registration and
//! L1 dispatched subscriptions. Frontend bindings (egui, Godot, Tauri,
//! future targets) consume this crate; they never reach into the kernel
//! directly.
//!
//! ## Discipline
//!
//! - No app-flavored namespace constants. Apps keep their own path
//!   helpers (`app/{app-id}/...`).
//! - No persistence I/O. Apps own their persistence strategy and feed
//!   the result into [`peer_manager::PeerManager::load_persisted`].
//! - No renderer / runtime assumptions. The SDK has no eframe, web-sys,
//!   gdext, raylib, or tview transitively — verified by per-crate
//!   feature-flag matrices in CI.
//! - No app-layer types in public APIs. Anything Tauri/Godot/web-only
//!   stays in the binding crate that consumes the SDK.
//!
//! See `bindings/sdk/README.md` for the discipline checklist and
//! contributor guidance.

pub mod sdk;
pub mod register_handler;
pub mod subscription;
pub mod peer_manager;
/// Inspect-sink routing (consumer side of the substrate's
/// dispatch/wire/binding hooks). Direct-arm install_inspect_sink
/// wiring. Worker-arm parallel lives on
/// `entity_wasm_worker_proxy::WorkerProxy`.
pub mod inspect;

/// Typed wrapper for `system/attestation` extension ops. Per
/// `EXTENSION-ATTESTATION.md §6` and `SDK-IDENTITY-INFRASTRUCTURE.md
/// §5.1` — signed-graph substrate ops. Reached via
/// `PeerContext::attestation()`.
#[cfg(feature = "attestation")]
pub mod attestation;

/// Typed wrapper for `system/clock` extension ops. Per
/// `SDK-EXTENSION-OPERATIONS.md §10` and `EXTENSION-CLOCK.md §3`.
/// Reached via `PeerContext::clock()`.
#[cfg(feature = "clock")]
pub mod clock;

#[cfg(feature = "compute")]
pub mod compute;

/// Typed wrapper for `system/continuation` extension ops. Per
/// `SDK-EXTENSION-OPERATIONS.md §2` (v0.7) — typed, discoverable
/// methods around `execute()`. Reached via `PeerContext::continuation()`.
#[cfg(feature = "continuation")]
pub mod continuation;

/// Typed wrapper for `system/identity` extension ops. Per
/// `EXTENSION-IDENTITY.md §6` and `SDK-IDENTITY-INFRASTRUCTURE.md §6`
/// — composition layer over attestation + quorum. Reached via
/// `PeerContext::identity()`.
#[cfg(feature = "identity")]
pub mod identity;

#[cfg(feature = "identity")]
pub mod identity_bootstrap;

#[cfg(feature = "identity")]
pub mod identity_bundle;

/// Typed wrapper for `system/quorum` extension ops. Per
/// `EXTENSION-QUORUM.md §6` and `SDK-IDENTITY-INFRASTRUCTURE.md
/// §5.2` — K-of-N node primitive substrate. Reached via
/// `PeerContext::quorum()`.
#[cfg(feature = "quorum")]
pub mod quorum;

/// State catch-up after silent saturation drops or peer-restart
/// downtime — wraps `revision:fetch-diff + tree:merge` per
/// `GUIDE-CONTINUATIONS-WORKBENCH §5`. Reached via
/// `PeerContext::reconcile_since_last_seen()`.
#[cfg(feature = "revision")]
pub mod reconcile;

/// Cross-peer chain capability mint + bundle per
/// `EXTENSION-CONTINUATION §4.2 case 3 / §8.2 C-3`. Methods on
/// `PeerContext`: `mint_cross_peer_chain_capability` and
/// `bundle_cross_peer_chain`.
pub mod cross_peer_cap;

/// Typed wrapper for `system/revision` extension ops. Per
/// `SDK-EXTENSION-OPERATIONS.md §4` (v0.7). Reached via
/// `PeerContext::revision()`.
#[cfg(feature = "revision")]
pub mod revision;

/// Typed wrapper for `system/role` extension ops. Per
/// `SDK-EXTENSION-OPERATIONS.md §13` and `EXTENSION-ROLE.md` v2.0.
/// Reached via `PeerContext::role()`.
#[cfg(feature = "role")]
pub mod role;

// Convenience re-exports of the most-used types so consumers can write
// `entity_sdk::PeerContext` rather than `entity_sdk::sdk::PeerContext`.
pub use sdk::{ChangeType, ContentRemoveOutcome, EntitySDK, FieldInfo, HandlerInfo, HistoryQueryOptions, HistoryQueryResult, HistoryTransition, InspectDispatchEvent, InspectWireDirection, InspectWireEvent, PeerContext, PeerContextBuilder, PeerMetadata, QueryMatch, QueryResults, SdkError, TreeChangeEvent, TypeInfo, content_remove_if_unbound};
pub use subscription::{SubscribeLimits, SubscribeOptions, SubscriptionInfo, SubscriptionOps};
pub use peer_manager::{PeerManager, PersistedPeer};
pub use inspect::{
    InspectBindingKind, InspectFact, InspectSinkFn, InspectSinkHandle, InspectSinkRegistry,
    InspectWireFrameDirection,
};

#[cfg(feature = "attestation")]
pub use attestation::{
    AttestationCreateResult, AttestationOps, AttestationRevokeResult, AttestationSupersedeResult,
    AttestationVerifyResult, NewAttestation,
};

#[cfg(feature = "clock")]
pub use clock::{ClockOps, ClockOrder, ClockState, ClockValue, HlcState};

#[cfg(feature = "compute")]
pub use compute::{
    ComputeEvalResult, ComputeInstallResult, ComputeOps, ComputeValue, EvalOptions,
    InstallOptions, InstalledSubgraph,
};

#[cfg(feature = "continuation")]
pub use continuation::ContinuationOps;

#[cfg(feature = "identity")]
pub use identity::{
    IdentityCreateAttestationResult, IdentityCreateQuorumResult, IdentityOps,
    IdentityPublishAttestationResult, IdentityRevokeAttestationResult,
    IdentitySupersedeAttestationResult, PublishMode,
};

#[cfg(feature = "identity")]
pub use identity_bootstrap::{BootstrapOptions, BootstrapResult, BootstrapStatus};

#[cfg(feature = "identity")]
pub use identity_bundle::IdentityBundle;

#[cfg(feature = "quorum")]
pub use quorum::{
    NewQuorum, QuorumCreateResult, QuorumOps, QuorumPublishResult, QuorumUpdateResult,
    QuorumVerifyResult,
};

#[cfg(feature = "revision")]
pub use reconcile::ReconcileResult;

#[cfg(feature = "revision")]
pub use revision::{
    CommitResult, ConfigResult, MergeConfigInput, MergeConfigResult, MergeResult,
    RevisionConfigInput, RevisionFetch, RevisionFetchDiff, RevisionFetchEntities, RevisionLog,
    RevisionOps, RevisionResolveResult, RevisionStatus,
};

#[cfg(feature = "role")]
pub use role::{
    RoleAssignResult, RoleDefineResult, RoleDelegateResult, RoleExcludeResult, RoleOps,
    RoleReDeriveResult, RoleUnassignResult, RoleUnexcludeResult,
};

/// Substrate-bridge extensions compiled into this build of `entity-sdk`.
///
/// Returns the canonical extension names whose Cargo features are
/// currently enabled. Each name maps to an `extensions/{name}/` crate
/// in entity-core-rust (or, for `"handlers"`, to `extensions/handler-ops/`
/// — the cargo feature name is preserved per CLAUDE.md).
///
/// The list is fixed at compile time and stable for the lifetime of
/// this binary. Today every `PeerContext` built in the same process
/// sees the same set; per-peer subsets are a Tier 2 future shape (per
/// the spawn-time `Config.extensions` ask). When that lands, this
/// free fn will keep returning "what could be enabled at all" while
/// [`PeerContext::installed_extensions`] diverges into per-peer
/// subsets.
///
/// **Why a free fn:** spawn-form UI (pre-Tier-2 `C.a.2`) needs to
/// prefill an extensions-checkbox grid before any peer exists. The
/// per-peer method (`PeerContext::installed_extensions`) requires a
/// PeerContext to call against; this entry point doesn't.
pub fn installed_extensions() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    #[cfg(feature = "attestation")]
    out.push("attestation");
    #[cfg(feature = "clock")]
    out.push("clock");
    #[cfg(feature = "compute")]
    out.push("compute");
    #[cfg(feature = "content")]
    out.push("content");
    #[cfg(feature = "continuation")]
    out.push("continuation");
    // Cargo-feature name preserved (CLAUDE.md): maps to
    // extensions/handler-ops/.
    #[cfg(feature = "handlers")]
    out.push("handlers");
    #[cfg(feature = "history")]
    out.push("history");
    #[cfg(feature = "identity")]
    out.push("identity");
    #[cfg(feature = "inbox")]
    out.push("inbox");
    #[cfg(feature = "local-files")]
    out.push("local-files");
    #[cfg(feature = "query")]
    out.push("query");
    #[cfg(feature = "quorum")]
    out.push("quorum");
    #[cfg(feature = "revision")]
    out.push("revision");
    #[cfg(feature = "role")]
    out.push("role");
    #[cfg(feature = "subscription")]
    out.push("subscription");
    #[cfg(feature = "type-system")]
    out.push("type-system");
    out
}

/// L1 SDK methods that are mirrored across the Web Worker boundary by
/// `wasm-worker-protocol` / `wasm-worker-proxy` / `wasm-worker-host`.
///
/// This is the **source of truth** for "what L1 surface gets a wire
/// variant." The wasm-worker crates assert at compile time (on wasm32)
/// that their `Request` variant set matches this list exactly. When you
/// add an L1 SDK method that should be reachable from a worker-hosted
/// consumer, append the variant name (PascalCase) here.
///
/// **What belongs in this list:** any `pub async fn` (or `pub fn`
/// returning a future) on `PeerContext` that consumers running through
/// the worker-proxy need to call. Order must match
/// `entity_wasm_worker_protocol::REQUEST_VARIANT_NAMES`.
///
/// **What does not belong:** L0 escape hatches (`store()`, `Scope`,
/// `peer()`, `peer_shared()`), wire-only primitives (`Init`,
/// `RegisterBackendPeer`), and worker-internal helpers. See
/// `bindings/wasm-worker-protocol/CONTRIBUTING.md` for boundary cases.
pub const L1_WORKER_MIRRORED_SURFACE: &[&str] = &[
    "Get",
    "Put",
    "PutCas",
    "List",
    "Remove",
    "Has",
    "Execute",
    "Query",
    "Count",
    "EntityCount",
    "PathCount",
    "InboxList",
    "InboxGet",
    "DiscoverHandlers",
    "DiscoverTypes",
    "Subscribe",
    "Unsubscribe",
    // history_query / history_rollback deferred to v1.1 per the protocol
    // convergence doc (egui doesn't use them today).
];
