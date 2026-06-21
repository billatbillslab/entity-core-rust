//! `IdentityOps::bootstrap` + `IdentityOps::bootstrap_status` — the L0
//! identity ceremony for a fresh peer.
//!
//! Phase 1 of the bootstrap shell-verb sketch. Composes substrate ops
//! (quorum entity + controller-cert
//! attestation + K-of-N signatures) and ends in a dispatched
//! `system/identity:configure` that mints the peer→controller
//! capability.
//!
//! ## Ceremony sequence
//!
//! Mirrors `workbench-go/entitysdk/identity_bootstrap.go::runBootstrap
//! Ceremony` end-to-end:
//!
//! 1. Persist the local peer's `system/peer` entity (already at hand
//!    via `peer.keypair().peer_entity()`); skip if already in the
//!    content store.
//! 2. Build + persist the quorum entity. Bind it at
//!    `/{peer_id}/system/quorum/{hex(quorum_hash)}`.
//! 3. Build + persist the controller-cert attestation (attesting =
//!    quorum_hash, attested = local identity_hash, properties =
//!    `{kind:"identity-cert", function:"controller", mode:"internal"}`
//!    plus caller-supplied custom properties).
//! 4. Sign the cert with each quorum member's keypair. Persist + bind
//!    each signature at `/{signer_peer_id}/system/signature/{hex(cert_
//!    hash)}` BEFORE the cert binding (so identity's process-
//!    attestation hook finds signatures already-bound when it fires
//!    on the cert bind).
//! 5. Bind the cert at `/{peer_id}/system/identity/internal/cert/
//!    {hex(cert_hash)}`. Triggers identity's process-attestation hook
//!    which validates K-of-N against the freshly-bound quorum.
//! 6. Dispatch `system/identity:configure` with `{trusts_quorum,
//!    controller_grants:[wildcard], bindings:[]}` and resource =
//!    `/{peer_id}/system/identity/peer-config`. The handler enumerates
//!    live controller certs anchored under `trusts_quorum`, verifies
//!    each, dedupes by `attested`, issues per-controller caps, and
//!    persists peer-config.
//!
//! ## Phase 1 scope
//!
//! - **1-of-1 self-quorum only.** The local peer is the sole signer.
//!   For `threshold > 1`, the wrapper would need to coordinate
//!   cross-peer signatures (the additional signers' keypairs live on
//!   other peers); that's Phase 2+. Phase 1 returns
//!   `multi_signer_unsupported` for any `threshold != 1`.
//! - **No bundle restore.** That's the IdentityBundle ask (a separate
//!   wrapper).
//! - **`force` re-bootstrap is documented but minimal.** Skips the
//!   AlreadyBootstrapped guard; per spec, identity is superseded
//!   not deleted, but Phase 1 doesn't yet construct supersedes-
//!   chained certs — re-running with `force=true` will produce a
//!   second cert under the same quorum. Real recovery scenarios
//!   should wait for a dedicated `recover_identity` API.

use crate::identity::{future_boxed, IdentityOps};
use crate::sdk::SdkError;
use ciborium::Value;
use entity_capability::{encode_grant_entry, CapabilityToken, GrantEntry, IdScope, PathScope};
use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_handler::{ExecuteOptions, HandlerResult};
use entity_hash::Hash;
use entity_peer::PeerShared;
use entity_store::{ContentStore, LocationIndex};
use entity_tree::TreeHandler;
use entity_types::{SignatureData, TYPE_ATTESTATION, TYPE_QUORUM};
use std::sync::Arc;

/// Configuration for [`IdentityOps::bootstrap`]. Defaults produce a
/// 1-of-1 self-quorum with wildcard controller grants and no label —
/// the smallest spec-conformant identity-aware peer.
#[derive(Debug, Clone)]
pub struct BootstrapOptions {
    /// Threshold K in K-of-N. Phase 1 supports only `1` (self-quorum);
    /// higher values return [`SdkError::HandlerError`] with code
    /// `multi_signer_unsupported`.
    pub quorum_threshold: usize,
    /// Identity hashes of additional signers for `threshold > 1`.
    /// Phase 1 ignores this field (multi-signer not yet supported);
    /// kept on the type for forward compatibility.
    pub additional_signers: Vec<Hash>,
    /// Human-readable label attached to the quorum entity. The
    /// quorum's `name` field; nothing else reads it.
    pub label: Option<String>,
    /// Caller-supplied properties merged into the controller-cert
    /// attestation. Bootstrap injects the spec-required keys
    /// (`kind`, `function`, `mode`) and these are appended; callers
    /// SHOULD NOT include those three keys themselves.
    pub properties: Vec<(String, Value)>,
    /// When `true`, skip the AlreadyBootstrapped guard and run the
    /// ceremony anyway. Phase 1: minimal — does not construct
    /// supersedes chains, so the new cert simply joins the existing
    /// set under the same quorum. Use only in recovery contexts.
    pub force: bool,
}

impl Default for BootstrapOptions {
    fn default() -> Self {
        Self {
            quorum_threshold: 1,
            additional_signers: vec![],
            label: None,
            properties: vec![],
            force: false,
        }
    }
}

/// Outcome of [`IdentityOps::bootstrap`].
#[derive(Debug, Clone)]
pub enum BootstrapResult {
    /// Peer already had a published peer-config — the ceremony was
    /// not re-run. `identity_hash` is the local peer's identity (read
    /// from `PeerContext::identity_hash`); `quorum_id` is the
    /// `trusts_quorum` recorded in the existing peer-config.
    AlreadyBootstrapped {
        identity_hash: Hash,
        quorum_id: Hash,
    },
    /// Ceremony ran to completion.
    Bootstrapped {
        /// Local peer's identity-entity content hash.
        identity_hash: Hash,
        /// Hash of the quorum entity (`system/quorum`) freshly minted.
        quorum_id: Hash,
        /// Hash of the controller-cert attestation
        /// (`system/attestation`) bound at
        /// `system/identity/internal/cert/{hex(controller_cert)}`.
        controller_cert: Hash,
        /// Tree path where the peer-config landed
        /// (`/{peer_id}/system/identity/peer-config`).
        peer_config_path: String,
        /// Hashes of per-controller capabilities the configure op
        /// issued. Typically one entry — the local peer→controller
        /// cap.
        issued_caps: Vec<Hash>,
    },
}

/// Snapshot view returned by [`IdentityOps::bootstrap_status`].
#[derive(Debug, Clone)]
pub struct BootstrapStatus {
    /// `true` iff the peer's peer-config entity is present at
    /// `/{peer_id}/system/identity/peer-config`.
    pub bootstrapped: bool,
    /// Local identity hash; always populated, regardless of
    /// `bootstrapped`. (The local peer always has an identity hash —
    /// what bootstrap establishes is the identity *stack*, not the
    /// identity itself.)
    pub identity_hash: Hash,
    /// Quorum hash read from peer-config, if bootstrapped.
    pub quorum_id: Option<Hash>,
    /// Tree path of the peer-config, if bootstrapped.
    pub peer_config_path: Option<String>,
}

/// Owned snapshot of the `PeerContext` state the bootstrap +
/// restore ceremonies need. Captured at the synchronous entry point so
/// the returned future does not borrow `&self`. Mirrors the pattern
/// `PeerContext::execute` uses (clone Arcs + small Copy state up
/// front; run the rest in an `async move` block).
pub(crate) struct BootstrapInputs {
    pub(crate) shared: Arc<PeerShared>,
    pub(crate) owner_cap: CapabilityToken,
    pub(crate) peer_id: String,
    pub(crate) identity_hash: Hash,
    pub(crate) keypair: Keypair,
    pub(crate) content_store: Arc<dyn ContentStore>,
    pub(crate) location_index: Arc<dyn LocationIndex>,
    pub(crate) tree: Arc<TreeHandler>,
}

impl BootstrapInputs {
    pub(crate) fn from_ctx(ctx: &crate::sdk::PeerContext) -> Self {
        Self {
            shared: ctx.shared.clone(),
            owner_cap: ctx.owner_self_cap.clone(),
            peer_id: ctx.peer_id().to_string(),
            identity_hash: ctx.identity_hash(),
            keypair: ctx
                .peer()
                .keypair()
                .as_ed25519()
                .expect("entity-sdk peers are Ed25519-only (Ed448 backends use core PeerBuilder)")
                .clone_inner(),
            content_store: ctx.peer().content_store().clone(),
            location_index: ctx.peer().location_index().clone(),
            tree: ctx.peer().tree().clone(),
        }
    }
}

impl<'a> IdentityOps<'a> {
    /// Run the L0 identity bootstrap ceremony. Idempotent — returns
    /// [`BootstrapResult::AlreadyBootstrapped`] if a peer-config is
    /// already published at `/{peer_id}/system/identity/peer-config`
    /// (unless `opts.force` is set).
    ///
    /// Returns a `'static` future so consumers wiring through a
    /// `BoxFuture<'static, _>` trait method (`PeerBinding::
    /// bootstrap_identity` and friends) can drive it without cloning
    /// `PeerContext`. Internally captures the needed Arcs + owned
    /// state up front, then runs the ceremony in an `async move`
    /// block. Mirrors `PeerContext::execute`'s shape.
    ///
    /// See the module-level doc for the ceremony sequence.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn bootstrap(
        &self,
        opts: BootstrapOptions,
    ) -> impl std::future::Future<Output = Result<BootstrapResult, SdkError>> + Send + 'static
    {
        let inputs = BootstrapInputs::from_ctx(self.ctx_ref());
        future_boxed(run_bootstrap(inputs, opts))
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn bootstrap(
        &self,
        opts: BootstrapOptions,
    ) -> impl std::future::Future<Output = Result<BootstrapResult, SdkError>> + 'static {
        let inputs = BootstrapInputs::from_ctx(self.ctx_ref());
        future_boxed(run_bootstrap(inputs, opts))
    }

    /// Read whether the peer is bootstrapped. Sync L0 access — does
    /// not dispatch.
    pub fn bootstrap_status(&self) -> BootstrapStatus {
        let ctx = self.ctx_ref();
        bootstrap_status_owned(
            ctx.peer_id(),
            ctx.identity_hash(),
            ctx.peer().tree().as_ref(),
        )
    }
}

/// Sync L0 status read against owned inputs. Shared by
/// [`IdentityOps::bootstrap_status`] and the restore short-circuit
/// path so the latter doesn't need to borrow `&PeerContext` from
/// inside its `'static` future.
pub(crate) fn bootstrap_status_owned(
    peer_id: &str,
    identity_hash: Hash,
    tree: &TreeHandler,
) -> BootstrapStatus {
    let path = format!("/{}/{}", peer_id, "system/identity/peer-config");
    let Some(entity) = tree.get(&path) else {
        return BootstrapStatus {
            bootstrapped: false,
            identity_hash,
            quorum_id: None,
            peer_config_path: None,
        };
    };
    let quorum_id = decode_peer_config_trusts_quorum(&entity);
    BootstrapStatus {
        bootstrapped: true,
        identity_hash,
        quorum_id,
        peer_config_path: Some(path),
    }
}

/// Read `trusts_quorum` out of a peer-config entity. Returns `None`
/// if the entity is malformed.
fn decode_peer_config_trusts_quorum(entity: &Entity) -> Option<Hash> {
    let val: Value = ciborium::de::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("trusts_quorum") {
            if let Value::Bytes(b) = v {
                return Hash::from_bytes(b).ok();
            }
        }
    }
    None
}

/// Run the bootstrap ceremony against an owned [`BootstrapInputs`]
/// snapshot. The async body owns its captures so the returned future
/// is `'static` — see [`IdentityOps::bootstrap`] for the outer
/// signature.
async fn run_bootstrap(
    inputs: BootstrapInputs,
    opts: BootstrapOptions,
) -> Result<BootstrapResult, SdkError> {
    // ---- Validate options ----
    if opts.quorum_threshold == 0 {
        return Err(SdkError::HandlerError(
            "bootstrap: quorum_threshold must be ≥ 1".into(),
        ));
    }
    if opts.quorum_threshold != 1 {
        // Phase 1 limitation: multi-signer needs cross-peer signature
        // coordination the SDK doesn't have yet. Flagging here rather
        // than silently using only the local keypair.
        return Err(SdkError::HandlerError(format!(
            "bootstrap: multi_signer_unsupported — quorum_threshold = {} requires cross-peer signature coordination not yet implemented in Phase 1. Use threshold = 1 for self-quorum.",
            opts.quorum_threshold
        )));
    }

    let BootstrapInputs {
        shared,
        owner_cap,
        peer_id: pid,
        identity_hash,
        keypair,
        content_store,
        location_index,
        tree,
    } = inputs;
    let peer_config_path = format!("/{}/system/identity/peer-config", pid);

    // ---- Idempotency guard ----
    if !opts.force {
        if let Some(existing) = tree.get(&peer_config_path) {
            let quorum_id = decode_peer_config_trusts_quorum(&existing).ok_or_else(|| {
                SdkError::HandlerError(
                    "bootstrap: peer-config present but malformed (no trusts_quorum)".into(),
                )
            })?;
            return Ok(BootstrapResult::AlreadyBootstrapped {
                identity_hash,
                quorum_id,
            });
        }
    }

    // ---- 1. Ensure local peer identity entity is in the content store ----
    let peer_entity = keypair
        .peer_entity()
        .map_err(|e| SdkError::HandlerError(format!("bootstrap: encode peer entity: {}", e)))?;
    if peer_entity.content_hash != identity_hash {
        // Sanity: this should never fire — PeerShared.identity_hash is
        // computed from the same keypair.peer_entity(). If it does, the
        // local identity has drifted from the cached hash and the
        // ceremony would produce mismatched signers; fail-closed.
        return Err(SdkError::HandlerError(format!(
            "bootstrap: peer_entity hash ({:?}) != ctx.identity_hash ({:?})",
            peer_entity.content_hash, identity_hash
        )));
    }
    let _ = content_store.put(peer_entity);

    // ---- 2. Build + bind the quorum entity ----
    let quorum_entity = build_quorum_entity(&[identity_hash], 1, opts.label.as_deref())?;
    let quorum_id = quorum_entity.content_hash;
    let quorum_path = format!("/{}/system/quorum/{}", pid, hex_segment(&quorum_id));
    content_store
        .put(quorum_entity)
        .map_err(|e| SdkError::HandlerError(format!("bootstrap: store quorum: {}", e)))?;
    location_index.set(&quorum_path, quorum_id);

    // ---- 3. Build + store the controller cert ----
    let cert_props = build_controller_cert_properties(&opts.properties);
    let cert_entity = build_attestation_entity(quorum_id, identity_hash, &cert_props)?;
    let cert_hash = cert_entity.content_hash;
    content_store
        .put(cert_entity)
        .map_err(|e| SdkError::HandlerError(format!("bootstrap: store cert: {}", e)))?;

    // ---- 4. Sign + bind signatures (BEFORE the cert binding) ----
    sign_and_bind_cert(
        content_store.as_ref(),
        location_index.as_ref(),
        &keypair,
        identity_hash,
        cert_hash,
    )?;

    // ---- 5. Bind the cert ----
    let cert_path = format!(
        "/{}/system/identity/internal/cert/{}",
        pid,
        hex_segment(&cert_hash)
    );
    location_index.set(&cert_path, cert_hash);

    // ---- 6. Dispatch system/identity:configure ----
    let controller_grants = vec![wildcard_grant()];
    let params = build_configure_params(quorum_id, &controller_grants)?;
    let opts_exec = ExecuteOptions {
        resource: Some(entity_capability::ResourceTarget {
            targets: vec![peer_config_path.clone()],
            exclude: vec![],
        }),
        ..Default::default()
    };
    let result = execute_owned(
        shared,
        owner_cap,
        "system/identity",
        "configure",
        params,
        opts_exec,
    )
    .await?;
    if let Some(err) = SdkError::from_handler_result(&result, "bootstrap: configure") {
        return Err(err);
    }
    let (returned_path, issued_caps) = decode_configure_result(&result.result)?;

    Ok(BootstrapResult::Bootstrapped {
        identity_hash,
        quorum_id,
        controller_cert: cert_hash,
        peer_config_path: returned_path.unwrap_or(peer_config_path),
        issued_caps,
    })
}

/// Owned-state dispatch helper — mirrors `PeerContext::execute` but
/// takes already-cloned `shared` + `owner_cap` so the returned future
/// is `'static` and reusable from the bootstrap + restore ceremonies.
/// Used in place of `ctx.execute(...)` after the ceremony has
/// destructured `BootstrapInputs` / `RestoreInputs`.
pub(crate) fn execute_owned(
    shared: Arc<PeerShared>,
    owner_cap: CapabilityToken,
    handler: &str,
    operation: &str,
    params: Entity,
    opts: ExecuteOptions,
) -> impl std::future::Future<Output = Result<HandlerResult, SdkError>> + 'static {
    let handler = handler.to_string();
    let operation = operation.to_string();
    async move {
        let local_identity = shared.identity_hash;
        let execute_fn = entity_peer::connection::make_execute_fn(
            shared,
            Some(local_identity),
            std::collections::HashMap::new(),
            None,
            Some(owner_cap),
        );
        execute_fn(handler, operation, params, opts)
            .await
            .map_err(|e| SdkError::HandlerError(e.to_string()))
    }
}

/// Hex-encode a hash to a lowercase string. Matches
/// `entity_attestation::hex_segment` / `entity_quorum::hex_segment`
/// (same algorithm, kept local to avoid pulling those crates as direct
/// deps).
fn hex_segment(h: &Hash) -> String {
    let bytes = h.to_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Build the `system/quorum` entity matching
/// `entity_quorum::QuorumData::to_entity()`. ECF-sorted: metadata,
/// name, signer_resolution, signers, threshold. We omit metadata +
/// signer_resolution for the bootstrap default.
fn build_quorum_entity(
    signers: &[Hash],
    threshold: u64,
    name: Option<&str>,
) -> Result<Entity, SdkError> {
    let mut fields: Vec<(Value, Value)> = Vec::new();
    if let Some(n) = name {
        fields.push((entity_ecf::text("name"), entity_ecf::text(n)));
    }
    fields.push((
        entity_ecf::text("signers"),
        Value::Array(
            signers
                .iter()
                .map(|h| Value::Bytes(h.to_bytes().to_vec()))
                .collect(),
        ),
    ));
    fields.push((
        entity_ecf::text("threshold"),
        entity_ecf::integer(threshold as i64),
    ));
    let data = entity_ecf::to_ecf(&Value::Map(fields));
    Entity::new(TYPE_QUORUM, data)
        .map_err(|e| SdkError::HandlerError(format!("encode quorum: {}", e)))
}

/// Build the controller-cert attestation entity matching
/// `entity_attestation::AttestationData::to_entity()`. ECF-sorted:
/// attested, attesting, expires_at, not_before, properties, supersedes.
/// Bootstrap omits expires/not_before/supersedes.
fn build_attestation_entity(
    attesting: Hash,
    attested: Hash,
    properties: &[(Value, Value)],
) -> Result<Entity, SdkError> {
    let mut fields: Vec<(Value, Value)> = Vec::new();
    fields.push((
        entity_ecf::text("attested"),
        Value::Bytes(attested.to_bytes().to_vec()),
    ));
    fields.push((
        entity_ecf::text("attesting"),
        Value::Bytes(attesting.to_bytes().to_vec()),
    ));
    if !properties.is_empty() {
        fields.push((entity_ecf::text("properties"), Value::Map(properties.to_vec())));
    }
    let data = entity_ecf::to_ecf(&Value::Map(fields));
    Entity::new(TYPE_ATTESTATION, data)
        .map_err(|e| SdkError::HandlerError(format!("encode attestation: {}", e)))
}

/// Compose the controller cert's `properties` field. Injects the
/// spec-required keys (`kind`, `function`, `mode`) and appends any
/// caller-supplied entries. ECF-sort happens at the `to_ecf` step.
fn build_controller_cert_properties(extra: &[(String, Value)]) -> Vec<(Value, Value)> {
    let mut props: Vec<(Value, Value)> = vec![
        (entity_ecf::text("function"), entity_ecf::text("controller")),
        (entity_ecf::text("kind"), entity_ecf::text("identity-cert")),
        (entity_ecf::text("mode"), entity_ecf::text("internal")),
    ];
    for (k, v) in extra {
        // Skip caller-provided values for the spec-pinned keys —
        // documented in BootstrapOptions::properties.
        if matches!(k.as_str(), "kind" | "function" | "mode") {
            continue;
        }
        props.push((entity_ecf::text(k), v.clone()));
    }
    // Sort by key text to match ECF map ordering invariants.
    props.sort_by(|(a, _), (b, _)| {
        let ak = a.as_text().unwrap_or("");
        let bk = b.as_text().unwrap_or("");
        ak.cmp(bk)
    });
    props
}

/// Sign the cert with the supplied signer keypair, persist the
/// signature entity, and bind it at the signer's namespace.
///
/// Path: `/{signer_peer_id}/system/signature/{hex(cert_hash)}`.
/// Signature target is the cert's content hash (33-byte wire form).
fn sign_and_bind_cert(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    signer: &Keypair,
    signer_identity: Hash,
    cert_hash: Hash,
) -> Result<(), SdkError> {
    let sig_bytes = signer.sign(&cert_hash.to_bytes()).to_vec();
    let sig_entity = SignatureData {
        target: cert_hash,
        signer: signer_identity,
        algorithm: "ed25519".to_string(),
        signature: sig_bytes,
    }
    .to_entity()
    .map_err(|e| SdkError::HandlerError(format!("encode signature: {}", e)))?;

    let sig_hash = sig_entity.content_hash;
    content_store
        .put(sig_entity)
        .map_err(|e| SdkError::HandlerError(format!("store signature: {}", e)))?;

    let signer_peer_id = signer.peer_id().to_string();
    let sig_path = format!(
        "/{}/system/signature/{}",
        signer_peer_id,
        hex_segment(&cert_hash)
    );
    location_index.set(&sig_path, sig_hash);
    Ok(())
}

/// Single wildcard grant matching `workbench-go`'s
/// `normalizeBootstrapOpts` default — `{handlers:"*", resources:"*",
/// operations:"*", peers:None}`. Used when caller did not supply
/// custom `controller_grants`.
fn wildcard_grant() -> GrantEntry {
    GrantEntry {
        handlers: PathScope::new(vec!["*".into()]),
        resources: PathScope::new(vec!["*".into()]),
        operations: IdScope::new(vec!["*".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }
}

/// Build the configure params body. ECF-sorted: bindings,
/// controller_grants, trusts_quorum. Bootstrap omits bindings (Phase
/// 1 doesn't support handle/agent binding rituals).
fn build_configure_params(
    trusts_quorum: Hash,
    controller_grants: &[GrantEntry],
) -> Result<Entity, SdkError> {
    let fields: Vec<(Value, Value)> = vec![
        (
            entity_ecf::text("controller_grants"),
            Value::Array(controller_grants.iter().map(encode_grant_entry).collect()),
        ),
        (
            entity_ecf::text("trusts_quorum"),
            Value::Bytes(trusts_quorum.to_bytes().to_vec()),
        ),
    ];
    let data = entity_ecf::to_ecf(&Value::Map(fields));
    Entity::new("primitive/any", data)
        .map_err(|e| SdkError::HandlerError(format!("encode configure params: {}", e)))
}

/// Decode the `configure_result` entity (see
/// `extensions/identity/src/handler.rs::configure_result`):
/// `{peer_config_path: text, issued_caps: [bytes]?}`.
fn decode_configure_result(entity: &Entity) -> Result<(Option<String>, Vec<Hash>), SdkError> {
    let val: Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode configure result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("configure result not a map".into()))?;

    let mut peer_config_path: Option<String> = None;
    let mut issued: Vec<Hash> = Vec::new();
    for (k, v) in map {
        match k.as_text() {
            Some("peer_config_path") => peer_config_path = v.as_text().map(|s| s.to_string()),
            Some("local_peer_to_controller_caps") => {
                if let Value::Array(arr) = v {
                    for item in arr {
                        if let Value::Bytes(b) = item {
                            if let Ok(h) = Hash::from_bytes(b) {
                                issued.push(h);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok((peer_config_path, issued))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::{PeerContext, PeerContextBuilder};

    fn make_ctx() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    /// Build-time contract check: `bootstrap` returns a future that
    /// can be moved into a `Pin<Box<dyn Future + Send + 'static>>` —
    /// the shape `PeerBinding::bootstrap_identity` needs. This is the
    /// blocker the eGUI side hit pre-refactor; the function being
    /// callable in this position is the gate. No runtime exercise
    /// needed — successful compile is the assertion.
    #[allow(dead_code)]
    fn bootstrap_future_is_static_send(ctx: &crate::sdk::PeerContext) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BootstrapResult, SdkError>> + Send + 'static>,
    > {
        Box::pin(ctx.identity().bootstrap(BootstrapOptions::default()))
    }

    /// Fresh peer reports not-bootstrapped; identity_hash is still
    /// populated (the local identity exists regardless of bootstrap).
    #[test]
    fn status_fresh_peer_reports_not_bootstrapped() {
        let ctx = make_ctx();
        let st = ctx.identity().bootstrap_status();
        assert!(!st.bootstrapped);
        assert!(st.quorum_id.is_none());
        assert!(st.peer_config_path.is_none());
        // identity_hash always present — non-zero.
        assert!(st.identity_hash.to_bytes().iter().any(|&b| b != 0));
    }

    /// Bootstrap with defaults on a fresh peer runs the ceremony and
    /// returns `Bootstrapped`. Verifies the full happy path —
    /// substrate composition + dispatched configure all wire up.
    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_default_runs_ceremony() {
        let ctx = make_ctx();
        let id = ctx.identity_hash();

        let r = ctx
            .identity()
            .bootstrap(BootstrapOptions::default())
            .await
            .expect("bootstrap should succeed");

        match r {
            BootstrapResult::Bootstrapped {
                identity_hash,
                quorum_id,
                controller_cert,
                peer_config_path,
                issued_caps,
            } => {
                assert_eq!(identity_hash, id);
                assert!(quorum_id.to_bytes().iter().any(|&b| b != 0));
                assert!(controller_cert.to_bytes().iter().any(|&b| b != 0));
                assert!(peer_config_path.ends_with("system/identity/peer-config"));
                assert!(!issued_caps.is_empty(), "configure must issue at least one local-peer cap");
            }
            other => panic!("expected Bootstrapped, got {:?}", other),
        }
    }

    /// After bootstrap, `bootstrap_status` reports bootstrapped =
    /// true and threads through the quorum hash from peer-config.
    #[tokio::test(flavor = "current_thread")]
    async fn status_after_bootstrap_reports_bootstrapped() {
        let ctx = make_ctx();
        let res = ctx
            .identity()
            .bootstrap(BootstrapOptions::default())
            .await
            .expect("bootstrap");
        let quorum = match res {
            BootstrapResult::Bootstrapped { quorum_id, .. } => quorum_id,
            other => panic!("expected Bootstrapped, got {:?}", other),
        };

        let st = ctx.identity().bootstrap_status();
        assert!(st.bootstrapped);
        assert_eq!(st.quorum_id, Some(quorum));
        assert!(st
            .peer_config_path
            .as_deref()
            .map(|p| p.ends_with("system/identity/peer-config"))
            .unwrap_or(false));
    }

    /// Re-running bootstrap on a peer that already has peer-config
    /// returns `AlreadyBootstrapped`. Idempotent on the no-op path.
    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_second_call_is_idempotent() {
        let ctx = make_ctx();
        let _ = ctx
            .identity()
            .bootstrap(BootstrapOptions::default())
            .await
            .expect("first bootstrap");

        let r2 = ctx
            .identity()
            .bootstrap(BootstrapOptions::default())
            .await
            .expect("second bootstrap should be idempotent");

        match r2 {
            BootstrapResult::AlreadyBootstrapped { identity_hash, .. } => {
                assert_eq!(identity_hash, ctx.identity_hash());
            }
            other => panic!("expected AlreadyBootstrapped, got {:?}", other),
        }
    }

    /// Phase 1 limit: threshold > 1 is rejected with a clear error.
    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_multi_signer_rejected_phase_1() {
        let ctx = make_ctx();
        let r = ctx
            .identity()
            .bootstrap(BootstrapOptions {
                quorum_threshold: 2,
                additional_signers: vec![Hash::from_bytes(&[0x00u8; 33]).unwrap()],
                ..Default::default()
            })
            .await;
        match r {
            Err(SdkError::HandlerError(msg)) if msg.contains("multi_signer_unsupported") => {}
            other => panic!("expected multi_signer_unsupported, got {:?}", other),
        }
    }

    /// Threshold 0 is rejected.
    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_threshold_zero_rejected() {
        let ctx = make_ctx();
        let r = ctx
            .identity()
            .bootstrap(BootstrapOptions {
                quorum_threshold: 0,
                ..Default::default()
            })
            .await;
        assert!(matches!(r, Err(SdkError::HandlerError(_))));
    }

    /// Custom label flows through to the quorum entity. We verify by
    /// reading the bound quorum entity back from the tree and decoding
    /// its `name` field.
    #[tokio::test(flavor = "current_thread")]
    async fn bootstrap_label_lands_on_quorum_entity() {
        let ctx = make_ctx();
        let res = ctx
            .identity()
            .bootstrap(BootstrapOptions {
                label: Some("my-test-quorum".into()),
                ..Default::default()
            })
            .await
            .expect("bootstrap");
        let qid = match res {
            BootstrapResult::Bootstrapped { quorum_id, .. } => quorum_id,
            other => panic!("expected Bootstrapped, got {:?}", other),
        };

        let qpath = format!(
            "/{}/system/quorum/{}",
            ctx.peer_id(),
            hex_segment(&qid)
        );
        let qe = ctx.store().get(&qpath).expect("quorum entity bound");
        let v: Value = ciborium::de::from_reader(qe.data.as_slice()).unwrap();
        let map = v.as_map().unwrap();
        let name = map
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("name") {
                    v.as_text().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        assert_eq!(name, "my-test-quorum");
    }
}
