//! Typed wrapper for `system/identity` extension operations.
//!
//! Per `EXTENSION-IDENTITY.md §6` and `SDK-IDENTITY-INFRASTRUCTURE.md §6`.
//! Reached via [`PeerContext::identity`].
//!
//! ## Scope
//!
//! The identity handler exposes seven operations per §6:
//! `configure`, `create_quorum`, `create_attestation`,
//! `supersede_attestation`, `revoke_attestation`, `publish_attestation`,
//! `process_attestation`. This module wraps **five** caller-issued ops:
//! `create_quorum`, `create_attestation`, `supersede_attestation`,
//! `revoke_attestation`, `publish_attestation`.
//!
//! ### Deliberately not wrapped here
//!
//! - **`configure`** — first-call requires the L0 in-process Startup
//!   path (§4.1 bootstrap exemption); subsequent re-configure goes
//!   through the dispatched form. Both surface as `BootstrapIdentity`
//!   per the handoff doc's Ask 4 (cross-impl identity-stack parity).
//!   Adding a thin wrapper here without that orchestration would mis-
//!   shape the consumer API; defer to the bootstrap landing.
//! - **`process_attestation`** — inbound delivery hook fired by the
//!   inbox runtime when a remote peer publishes an identity-context
//!   attestation. Not a caller-issued op. Workbench-go's
//!   `IdentityClient` correctly omits it too.
//!
//! ## Composition role
//!
//! Identity composes on **attestation** (signed-graph substrate) and
//! **quorum** (K-of-N substrate). The `create_quorum` op delegates
//! internally to `system/quorum:create` and additionally records the
//! resulting `quorum_id` in identity peer-config when the caller is
//! configured for it. `create_attestation` is the substrate `create`
//! plus §5.3 path dispatch — the handler computes the canonical
//! storage path from `properties.kind/function/mode/contact_id`.
//!
//! ## Antipattern guard (load-bearing)
//!
//! Per `GUIDE-SDK-PATTERNS.md §9`. Identity-context attestations MUST
//! route through `system/identity:create_attestation` (this wrapper),
//! NEVER through `system/attestation:create` directly — the identity
//! layer applies per-kind structural validation, mode/function gating
//! (§4.2 table), and canonical-path dispatch that the substrate-level
//! attestation handler does not. This is the surface Godot γ.4.2 hit
//! and got pulled back from.
//!
//! ## Wire shape (path-as-resource)
//!
//! Per `EXTENSION-IDENTITY §6` (R-3),
//! all five wrapped ops use path-as-resource. For ops that target a
//! computable canonical path, the SDK computes it locally and threads
//! it through `EXECUTE.resource.targets[0]`:
//!
//! - `create_quorum` → `system/quorum/{quorum_id_hex}` (matches
//!   substrate path; SDK computes `quorum_id` locally).
//! - `create_attestation` / `supersede_attestation` →
//!   `canonical_cert_path(mode, contact_id, att_hash)` per §5.3
//!   (`Embedded` mode returns no resource — the attestation is
//!   inlined in the result instead).
//! - `publish_attestation` → destination path per `new_mode`
//!   (`Internal` / `Public` / `PerRelationship`).
//! - `revoke_attestation` → no resource (handler dispatches by
//!   `target_hash`).
//!
//! ## Feature gating
//!
//! Available only when `entity-sdk` is built with the `identity`
//! feature enabled.

use crate::attestation::NewAttestation;
use crate::sdk::{PeerContext, SdkError};
use entity_capability::ResourceTarget;
use entity_entity::Entity;
use entity_handler::{ExecuteOptions, HandlerResult};
use entity_hash::Hash;
use entity_types::{
    TYPE_ATTESTATION, TYPE_IDENTITY_CREATE_ATTESTATION_REQUEST,
    TYPE_IDENTITY_CREATE_QUORUM_REQUEST, TYPE_IDENTITY_PUBLISH_ATTESTATION_REQUEST,
    TYPE_IDENTITY_REVOKE_ATTESTATION_REQUEST, TYPE_IDENTITY_SUPERSEDE_ATTESTATION_REQUEST,
    TYPE_QUORUM,
};

// ---------------------------------------------------------------------------
// Publication mode (mirror of extensions/identity/src/kinds.rs Mode)
// ---------------------------------------------------------------------------

/// Publication mode for cert audience tier (§4.2a). REQUIRED on all
/// `identity-cert` attestations per §4.2. Mirrors
/// `extensions/identity/src/kinds.rs::Mode` (SDK / extension-crate
/// boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishMode {
    /// Internal-tier: stored under `system/identity/internal/cert/`.
    Internal,
    /// Public-tier: stored under `system/identity/public/cert/`.
    Public,
    /// Per-relationship: stored under
    /// `system/identity/relationships/{contact_id}/cert/`. Requires
    /// a contact_id.
    PerRelationship,
    /// Embedded: not tree-resident; lives inline in cap envelopes.
    /// No tree path; result carries the inline attestation.
    Embedded,
}

impl PublishMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Public => "public",
            Self::PerRelationship => "per-relationship",
            Self::Embedded => "embedded",
        }
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Decoded result of `system/identity:create_quorum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityCreateQuorumResult {
    /// Content hash of the persisted `system/quorum` entity.
    pub quorum_id: Hash,
}

/// Decoded result of `system/identity:create_attestation`.
///
/// Per §6 R-6: in `Embedded` mode the result carries
/// `embedded_attestation` (inline AttestationData bytes) and **omits**
/// `attestation_hash`. In every other mode the handler binds the
/// attestation at `storage_path` and returns its hash.
#[derive(Debug, Clone)]
pub struct IdentityCreateAttestationResult {
    /// Hash of the persisted attestation. `None` for `Embedded` mode.
    pub attestation_hash: Option<Hash>,
    /// Canonical storage path the handler bound the attestation at.
    /// `None` for `Embedded` mode.
    pub storage_path: Option<String>,
    /// Inline attestation bytes for `Embedded` mode (the canonical
    /// `AttestationData::to_entity().data` encoding). `None` otherwise.
    /// Per R-6, the caller embeds this in a cap envelope or otherwise
    /// propagates it without re-encoding.
    pub embedded_attestation: Option<Vec<u8>>,
}

/// Decoded result of `system/identity:supersede_attestation`. Same
/// shape as create (handler returns `TYPE_IDENTITY_SUPERSEDE_..._RESULT`
/// with distinct tag).
#[derive(Debug, Clone)]
pub struct IdentitySupersedeAttestationResult {
    pub attestation_hash: Option<Hash>,
    pub storage_path: Option<String>,
}

/// Decoded result of `system/identity:revoke_attestation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityRevokeAttestationResult {
    /// Content hash of the newly-minted revocation attestation entity.
    pub revocation_hash: Hash,
}

/// Decoded result of `system/identity:publish_attestation` per R-9.
#[derive(Debug, Clone)]
pub struct IdentityPublishAttestationResult {
    /// The attestation hash that was moved.
    pub attestation_hash: Hash,
    /// The post-move canonical destination path. This is the entire
    /// return-value point of `publish_attestation` (R-9: pre-fix Rust
    /// returned the field as `storage_path`, breaking Go's decoder).
    pub new_path: String,
}

// ---------------------------------------------------------------------------
// Scope handle
// ---------------------------------------------------------------------------

/// Typed accessor for `system/identity` operations.
///
/// Created via [`PeerContext::identity`]. Borrows from the
/// `PeerContext`; futures returned by methods are `'static`.
pub struct IdentityOps<'a> {
    ctx: &'a PeerContext,
}

impl<'a> IdentityOps<'a> {
    pub(crate) fn new(ctx: &'a PeerContext) -> Self {
        Self { ctx }
    }

    /// Internal accessor — `identity_bootstrap` module composes
    /// substrate operations across the SDK boundary and needs the
    /// underlying `PeerContext`. Not exposed publicly.
    pub(crate) fn ctx_ref(&self) -> &'a PeerContext {
        self.ctx
    }

    /// Mint a `system/quorum` entity via the identity-context dispatch
    /// (§6.3). Internally delegates to `system/quorum:create` plus
    /// peer-config bookkeeping when the caller is configured for it.
    ///
    /// The SDK computes `quorum_id` locally (content hash of the
    /// canonical `system/quorum` body) and threads
    /// `system/quorum/{quorum_id_hex}` as the resource target — R-3
    /// strict, no canonical-path fallback at the handler.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn create_quorum(
        &self,
        signers: Vec<Hash>,
        threshold: u64,
        name: Option<String>,
    ) -> impl std::future::Future<Output = Result<IdentityCreateQuorumResult, SdkError>>
    + Send
    + 'static {
        let (params, path) = match build_identity_create_quorum_request(&signers, threshold, name) {
            Ok(pair) => pair,
            Err(e) => return future_ready(Err(e)),
        };
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/identity", "create_quorum", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "create_quorum", |e| {
                decode_hash_field(e, "quorum_id", "create_quorum-result")
                    .map(|quorum_id| IdentityCreateQuorumResult { quorum_id })
            })
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn create_quorum(
        &self,
        signers: Vec<Hash>,
        threshold: u64,
        name: Option<String>,
    ) -> impl std::future::Future<Output = Result<IdentityCreateQuorumResult, SdkError>> + 'static
    {
        let (params, path) = match build_identity_create_quorum_request(&signers, threshold, name) {
            Ok(pair) => pair,
            Err(e) => return future_ready(Err(e)),
        };
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/identity", "create_quorum", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "create_quorum", |e| {
                decode_hash_field(e, "quorum_id", "create_quorum-result")
                    .map(|quorum_id| IdentityCreateQuorumResult { quorum_id })
            })
        })
    }

    /// Mint an identity-context attestation (§6.4). The handler
    /// applies per-kind structural validation, §4.2 mode/function
    /// gating, and §5.3 path dispatch.
    ///
    /// `att.properties` MUST carry `kind` (required) and, for
    /// `identity-cert` kinds, `function` + `mode` (required) and
    /// `contact_id` (required when `mode = per-relationship`). The
    /// SDK reads these from properties to pre-compute the canonical
    /// path. For `Embedded` mode, no path is sent — the handler
    /// returns the inline attestation in the result.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn create_attestation(
        &self,
        att: NewAttestation,
    ) -> impl std::future::Future<Output = Result<IdentityCreateAttestationResult, SdkError>>
    + Send
    + 'static {
        let (params, path) = match build_identity_create_attestation_request(&att) {
            Ok(pair) => pair,
            Err(e) => return future_ready(Err(e)),
        };
        let opts = match path {
            Some(p) => path_resource_opts(p),
            None => ExecuteOptions::default(),
        };
        let fut = self
            .ctx
            .execute("system/identity", "create_attestation", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "create_attestation", decode_create_att_result)
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn create_attestation(
        &self,
        att: NewAttestation,
    ) -> impl std::future::Future<Output = Result<IdentityCreateAttestationResult, SdkError>> + 'static
    {
        let (params, path) = match build_identity_create_attestation_request(&att) {
            Ok(pair) => pair,
            Err(e) => return future_ready(Err(e)),
        };
        let opts = match path {
            Some(p) => path_resource_opts(p),
            None => ExecuteOptions::default(),
        };
        let fut = self
            .ctx
            .execute("system/identity", "create_attestation", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "create_attestation", decode_create_att_result)
        })
    }

    /// Mint a successor identity-context attestation per §6. The new
    /// attestation MUST set `att.supersedes` to the predecessor's
    /// content hash; the handler validates kind match.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn supersede_attestation(
        &self,
        new_att: NewAttestation,
    ) -> impl std::future::Future<Output = Result<IdentitySupersedeAttestationResult, SdkError>>
    + Send
    + 'static {
        let (params, path) =
            match build_identity_supersede_attestation_request(&new_att) {
                Ok(pair) => pair,
                Err(e) => return future_ready(Err(e)),
            };
        let opts = match path {
            Some(p) => path_resource_opts(p),
            None => ExecuteOptions::default(),
        };
        let fut = self
            .ctx
            .execute("system/identity", "supersede_attestation", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "supersede_attestation", decode_supersede_att_result)
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn supersede_attestation(
        &self,
        new_att: NewAttestation,
    ) -> impl std::future::Future<Output = Result<IdentitySupersedeAttestationResult, SdkError>> + 'static
    {
        let (params, path) =
            match build_identity_supersede_attestation_request(&new_att) {
                Ok(pair) => pair,
                Err(e) => return future_ready(Err(e)),
            };
        let opts = match path {
            Some(p) => path_resource_opts(p),
            None => ExecuteOptions::default(),
        };
        let fut = self
            .ctx
            .execute("system/identity", "supersede_attestation", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "supersede_attestation", decode_supersede_att_result)
        })
    }

    /// Produce a revocation attestation targeting an identity-context
    /// attestation per §6. The revocation is itself a
    /// `system/attestation` with `kind = "revocation"`. Callers MUST
    /// K-of-N sign it under the quorum's threshold for it to take
    /// effect on liveness; an unsigned revocation has no effect.
    ///
    /// No resource path — the handler dispatches by `target_hash`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn revoke_attestation(
        &self,
        target_hash: Hash,
        reason: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<IdentityRevokeAttestationResult, SdkError>>
    + Send
    + 'static {
        let params = build_identity_revoke_attestation_request(target_hash, &reason.into());
        let fut = self.ctx.execute(
            "system/identity",
            "revoke_attestation",
            params,
            ExecuteOptions::default(),
        );
        future_boxed(async move {
            decode_or_err(fut.await?, "revoke_attestation", |e| {
                decode_hash_field(e, "revocation_hash", "revoke_attestation-result")
                    .map(|revocation_hash| IdentityRevokeAttestationResult { revocation_hash })
            })
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn revoke_attestation(
        &self,
        target_hash: Hash,
        reason: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<IdentityRevokeAttestationResult, SdkError>> + 'static
    {
        let params = build_identity_revoke_attestation_request(target_hash, &reason.into());
        let fut = self.ctx.execute(
            "system/identity",
            "revoke_attestation",
            params,
            ExecuteOptions::default(),
        );
        future_boxed(async move {
            decode_or_err(fut.await?, "revoke_attestation", |e| {
                decode_hash_field(e, "revocation_hash", "revoke_attestation-result")
                    .map(|revocation_hash| IdentityRevokeAttestationResult { revocation_hash })
            })
        })
    }

    /// Promote/demote a `function="agent"` identity-cert across
    /// publication modes (Internal / Public / PerRelationship per
    /// §4.2a). `contact_id` is required when `new_mode =
    /// PerRelationship`.
    ///
    /// R-9: result field is `new_path` (the post-move canonical
    /// destination), not `storage_path`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn publish_attestation(
        &self,
        attestation_hash: Hash,
        new_mode: PublishMode,
        contact_id: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<IdentityPublishAttestationResult, SdkError>>
    + Send
    + 'static {
        let params =
            build_identity_publish_attestation_request(attestation_hash, new_mode, contact_id);
        let path = canonical_publish_path(attestation_hash, new_mode, contact_id);
        let opts = match path {
            Some(p) => path_resource_opts(p),
            None => ExecuteOptions::default(),
        };
        let fut = self
            .ctx
            .execute("system/identity", "publish_attestation", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "publish_attestation", decode_publish_att_result)
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn publish_attestation(
        &self,
        attestation_hash: Hash,
        new_mode: PublishMode,
        contact_id: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<IdentityPublishAttestationResult, SdkError>> + 'static
    {
        let params =
            build_identity_publish_attestation_request(attestation_hash, new_mode, contact_id);
        let path = canonical_publish_path(attestation_hash, new_mode, contact_id);
        let opts = match path {
            Some(p) => path_resource_opts(p),
            None => ExecuteOptions::default(),
        };
        let fut = self
            .ctx
            .execute("system/identity", "publish_attestation", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "publish_attestation", decode_publish_att_result)
        })
    }
}

// ---------------------------------------------------------------------------
// Path constructors (mirror extensions/identity/src/paths.rs)
// ---------------------------------------------------------------------------

pub(crate) fn path_internal_cert(att_hash: &Hash) -> String {
    format!("system/identity/internal/cert/{}", att_hash.to_hex())
}

pub(crate) fn path_public_cert(att_hash: &Hash) -> String {
    format!("system/identity/public/cert/{}", att_hash.to_hex())
}

pub(crate) fn path_relationship_cert(contact_id: &Hash, att_hash: &Hash) -> String {
    format!(
        "system/identity/relationships/{}/cert/{}",
        contact_id.to_hex(),
        att_hash.to_hex()
    )
}

pub(crate) fn canonical_cert_path(
    mode: PublishMode,
    contact_id: Option<Hash>,
    att_hash: &Hash,
) -> Option<String> {
    match mode {
        PublishMode::Internal => Some(path_internal_cert(att_hash)),
        PublishMode::Public => Some(path_public_cert(att_hash)),
        PublishMode::PerRelationship => contact_id.map(|c| path_relationship_cert(&c, att_hash)),
        PublishMode::Embedded => None,
    }
}

fn canonical_publish_path(
    attestation_hash: Hash,
    new_mode: PublishMode,
    contact_id: Option<Hash>,
) -> Option<String> {
    canonical_cert_path(new_mode, contact_id, &attestation_hash)
}

// ---------------------------------------------------------------------------
// Property scanning — read mode / contact_id out of NewAttestation
// properties without depending on entity-identity.
// ---------------------------------------------------------------------------

pub(crate) fn read_mode_from_properties(
    properties: &[(ciborium::Value, ciborium::Value)],
) -> Option<PublishMode> {
    for (k, v) in properties {
        if k.as_text() == Some("mode") {
            return v.as_text().and_then(|s| match s {
                "internal" => Some(PublishMode::Internal),
                "public" => Some(PublishMode::Public),
                "per-relationship" => Some(PublishMode::PerRelationship),
                "embedded" => Some(PublishMode::Embedded),
                _ => None,
            });
        }
    }
    None
}

pub(crate) fn read_contact_id_from_properties(
    properties: &[(ciborium::Value, ciborium::Value)],
) -> Option<Hash> {
    for (k, v) in properties {
        if k.as_text() == Some("contact_id") {
            if let ciborium::Value::Bytes(b) = v {
                return Hash::from_bytes(b).ok();
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Request encoders
// ---------------------------------------------------------------------------

fn path_resource_opts(path: String) -> ExecuteOptions {
    ExecuteOptions {
        resource: Some(ResourceTarget {
            targets: vec![path],
            exclude: vec![],
        }),
        ..Default::default()
    }
}

fn build_identity_create_quorum_request(
    signers: &[Hash],
    threshold: u64,
    name: Option<String>,
) -> Result<(Entity, String), SdkError> {
    // The request shape mirrors QuorumData (the handler reads signers,
    // threshold, name, metadata directly from params and recomputes
    // the canonical quorum body for R-3 path validation).
    //
    // ECF order: metadata, name, signer_resolution, signers, threshold.
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    if let Some(n) = &name {
        fields.push((entity_ecf::text("name"), entity_ecf::text(n)));
    }
    fields.push((
        entity_ecf::text("signers"),
        ciborium::Value::Array(
            signers
                .iter()
                .map(|h| ciborium::Value::Bytes(h.to_bytes().to_vec()))
                .collect(),
        ),
    ));
    fields.push((
        entity_ecf::text("threshold"),
        entity_ecf::integer(threshold as i64),
    ));

    // Compute the canonical quorum_id from the same body shape the
    // handler builds (R-4 byte fidelity). Fields are already sorted
    // (metadata absent, name < signers < signer_resolution? we omit
    // signer_resolution + metadata so ordering is name < signers <
    // threshold — ECF-correct).
    let body_data = entity_ecf::to_ecf(&ciborium::Value::Map(fields.clone()));
    let q_entity = Entity::new(TYPE_QUORUM, body_data)
        .map_err(|e| SdkError::HandlerError(format!("compute quorum_id: {}", e)))?;
    let quorum_id = q_entity.content_hash;

    let req_data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    let req_entity = Entity::new(TYPE_IDENTITY_CREATE_QUORUM_REQUEST, req_data)
        .map_err(|e| SdkError::HandlerError(format!("encode create_quorum-request: {}", e)))?;

    Ok((req_entity, format!("system/quorum/{}", quorum_id.to_hex())))
}

fn build_identity_create_attestation_request(
    att: &NewAttestation,
) -> Result<(Entity, Option<String>), SdkError> {
    // Request shape mirrors attestation-substrate create-request:
    //   {attested, attesting, expires_at?, not_before?, properties?,
    //    supersedes?}
    // Identity-specific routing (kind/function/mode/contact_id) lives
    // nested inside `properties`.
    let req_entity = build_att_envelope(TYPE_IDENTITY_CREATE_ATTESTATION_REQUEST, att);

    // Compute the canonical storage path the handler would derive.
    let mode = read_mode_from_properties(&att.properties);
    let contact_id = read_contact_id_from_properties(&att.properties);

    // Compute the att_hash from the equivalent substrate attestation
    // entity (the handler builds the same shape via
    // AttestationData::to_entity()).
    let att_substrate = build_att_envelope(TYPE_ATTESTATION, att);
    let path = match mode {
        Some(m) => canonical_cert_path(m, contact_id, &att_substrate.content_hash),
        None => None,
    };

    Ok((req_entity, path))
}

fn build_identity_supersede_attestation_request(
    new_att: &NewAttestation,
) -> Result<(Entity, Option<String>), SdkError> {
    let req_entity = build_att_envelope(TYPE_IDENTITY_SUPERSEDE_ATTESTATION_REQUEST, new_att);

    let mode = read_mode_from_properties(&new_att.properties);
    let contact_id = read_contact_id_from_properties(&new_att.properties);
    let att_substrate = build_att_envelope(TYPE_ATTESTATION, new_att);
    let path = match mode {
        Some(m) => canonical_cert_path(m, contact_id, &att_substrate.content_hash),
        None => None,
    };

    Ok((req_entity, path))
}

/// Build a CBOR-encoded attestation-shaped entity. Used both for the
/// substrate `system/attestation` body (to compute att_hash for path
/// derivation) and for the identity request entities (which carry the
/// same field set, distinguished only by entity_type). ECF order:
/// attested, attesting, expires_at, not_before, properties, supersedes.
fn build_att_envelope(entity_type: &str, att: &NewAttestation) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            entity_ecf::text("attested"),
            ciborium::Value::Bytes(att.attested.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("attesting"),
            ciborium::Value::Bytes(att.attesting.to_bytes().to_vec()),
        ),
    ];
    if let Some(ts) = att.expires_at {
        fields.push((
            entity_ecf::text("expires_at"),
            entity_ecf::integer(ts as i64),
        ));
    }
    if let Some(ts) = att.not_before {
        fields.push((
            entity_ecf::text("not_before"),
            entity_ecf::integer(ts as i64),
        ));
    }
    if !att.properties.is_empty() {
        fields.push((
            entity_ecf::text("properties"),
            ciborium::Value::Map(att.properties.clone()),
        ));
    }
    if let Some(s) = att.supersedes {
        fields.push((
            entity_ecf::text("supersedes"),
            ciborium::Value::Bytes(s.to_bytes().to_vec()),
        ));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(entity_type, data).expect("attestation envelope construction is infallible")
}

fn build_identity_revoke_attestation_request(target_hash: Hash, reason: &str) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![(
        entity_ecf::text("target_hash"),
        ciborium::Value::Bytes(target_hash.to_bytes().to_vec()),
    )];
    if !reason.is_empty() {
        fields.push((entity_ecf::text("reason"), entity_ecf::text(reason)));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_IDENTITY_REVOKE_ATTESTATION_REQUEST, data)
        .expect("revoke-request entity construction is infallible")
}

fn build_identity_publish_attestation_request(
    attestation_hash: Hash,
    new_mode: PublishMode,
    contact_id: Option<Hash>,
) -> Entity {
    // ECF order: attestation_hash, contact_id, new_mode.
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![(
        entity_ecf::text("attestation_hash"),
        ciborium::Value::Bytes(attestation_hash.to_bytes().to_vec()),
    )];
    if let Some(c) = contact_id {
        fields.push((
            entity_ecf::text("contact_id"),
            ciborium::Value::Bytes(c.to_bytes().to_vec()),
        ));
    }
    fields.push((
        entity_ecf::text("new_mode"),
        entity_ecf::text(new_mode.as_str()),
    ));
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_IDENTITY_PUBLISH_ATTESTATION_REQUEST, data)
        .expect("publish-request entity construction is infallible")
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

fn decode_or_err<T>(
    result: HandlerResult,
    op: &'static str,
    decode: impl FnOnce(&Entity) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    if let Some(err) = SdkError::from_handler_result(&result, format!("system/identity:{op}")) {
        return Err(err);
    }
    decode(&result.result)
}

fn decode_hash_field(
    entity: &Entity,
    field: &'static str,
    ctx: &'static str,
) -> Result<Hash, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode {}: {}", ctx, e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError(format!("{} not a map", ctx)))?;
    for (k, v) in map {
        if k.as_text() == Some(field) {
            if let ciborium::Value::Bytes(b) = v {
                if let Ok(h) = Hash::from_bytes(b) {
                    return Ok(h);
                }
            }
        }
    }
    Err(SdkError::HandlerError(format!(
        "{} missing field `{}`",
        ctx, field
    )))
}

fn decode_create_att_result(
    entity: &Entity,
) -> Result<IdentityCreateAttestationResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode create-attestation-result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("create-attestation-result not a map".into()))?;

    let mut attestation_hash: Option<Hash> = None;
    let mut storage_path: Option<String> = None;
    let mut embedded_attestation: Option<Vec<u8>> = None;

    for (k, v) in map {
        match k.as_text() {
            Some("attestation_hash") => {
                if let ciborium::Value::Bytes(b) = v {
                    attestation_hash = Hash::from_bytes(b).ok();
                }
            }
            Some("storage_path") => {
                storage_path = v.as_text().map(|s| s.to_string());
            }
            Some("embedded_attestation") => {
                // Re-encode the inline sub-map to canonical ECF bytes so
                // the caller can embed it without further work. Matches
                // R-6's "bytes produced by AttestationData::to_entity().data".
                embedded_attestation = Some(entity_ecf::to_ecf(v));
            }
            _ => {}
        }
    }

    Ok(IdentityCreateAttestationResult {
        attestation_hash,
        storage_path,
        embedded_attestation,
    })
}

fn decode_supersede_att_result(
    entity: &Entity,
) -> Result<IdentitySupersedeAttestationResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode supersede-attestation-result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("supersede-attestation-result not a map".into()))?;

    let mut attestation_hash: Option<Hash> = None;
    let mut storage_path: Option<String> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("attestation_hash") => {
                if let ciborium::Value::Bytes(b) = v {
                    attestation_hash = Hash::from_bytes(b).ok();
                }
            }
            Some("storage_path") => storage_path = v.as_text().map(|s| s.to_string()),
            _ => {}
        }
    }
    Ok(IdentitySupersedeAttestationResult {
        attestation_hash,
        storage_path,
    })
}

fn decode_publish_att_result(
    entity: &Entity,
) -> Result<IdentityPublishAttestationResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode publish-attestation-result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("publish-attestation-result not a map".into()))?;

    let mut attestation_hash: Option<Hash> = None;
    let mut new_path: Option<String> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("attestation_hash") => {
                if let ciborium::Value::Bytes(b) = v {
                    attestation_hash = Hash::from_bytes(b).ok();
                }
            }
            Some("new_path") => new_path = v.as_text().map(|s| s.to_string()),
            _ => {}
        }
    }
    Ok(IdentityPublishAttestationResult {
        attestation_hash: attestation_hash
            .ok_or_else(|| SdkError::HandlerError("publish-result missing attestation_hash".into()))?,
        new_path: new_path
            .ok_or_else(|| SdkError::HandlerError("publish-result missing new_path".into()))?,
    })
}

// ---------------------------------------------------------------------------
// Future helpers (matching quorum.rs pattern)
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn future_ready<T: Send + 'static>(
    v: Result<T, SdkError>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SdkError>> + Send + 'static>> {
    Box::pin(async move { v })
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn future_ready<T: 'static>(
    v: Result<T, SdkError>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SdkError>> + 'static>> {
    Box::pin(async move { v })
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn future_boxed<
    T: Send + 'static,
    F: std::future::Future<Output = Result<T, SdkError>> + Send + 'static,
>(
    f: F,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SdkError>> + Send + 'static>> {
    Box::pin(f)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn future_boxed<T: 'static, F: std::future::Future<Output = Result<T, SdkError>> + 'static>(
    f: F,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SdkError>> + 'static>> {
    Box::pin(f)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::PeerContextBuilder;

    fn make_ctx() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    /// `create_quorum` via identity dispatch returns a quorum_id.
    /// Probes: SDK-computed quorum_id matches handler-computed
    /// canonical path; result decoder lifts the hash bytes.
    #[tokio::test(flavor = "current_thread")]
    async fn create_quorum_returns_quorum_id() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        let r = ctx
            .identity()
            .create_quorum(vec![me], 1, Some("test".into()))
            .await
            .expect("create_quorum should dispatch");
        assert!(
            r.quorum_id.to_bytes().iter().any(|&b| b != 0),
            "quorum_id non-zero"
        );
    }

    /// `revoke_attestation` requires its target in the identity
    /// attestation index per §3.6 (the chain walk back to the trusted
    /// quorum needs an actual target). A synthetic target produces
    /// `404 target_not_found`. Probes that the wrapper threads
    /// target_hash + reason correctly and the handler returns a
    /// structured error rather than panicking.
    ///
    /// A full success-path test requires seeding a quorum-rooted
    /// identity-cert chain (multi-op setup); deferred to integration
    /// tests once the bootstrap/identity-bundle helpers land (Ask 4).
    #[tokio::test(flavor = "current_thread")]
    async fn revoke_attestation_unindexed_target_returns_404() {
        let ctx = make_ctx();
        let target = Hash::from_bytes(&[0x00u8; 33]).expect("zero hash");
        let r = ctx
            .identity()
            .revoke_attestation(target, "test revocation")
            .await;
        match r {
            Err(SdkError::NotFound { status: 404, code, .. })
                if code.as_deref() == Some("target_not_found") => {}
            other => panic!(
                "expected 404 target_not_found for synthetic hash, got {:?}",
                other
            ),
        }
    }

    /// `create_attestation` with malformed properties returns a
    /// structured 400 from the handler's per-kind validation (§4).
    /// Probes: the SDK threads attesting/attested/properties through
    /// to the identity handler, kind/function/mode extraction works,
    /// the wrapper surfaces the handler error without panic.
    ///
    /// Success-path coverage requires a quorum-rooted identity-cert
    /// chain — deferred to integration tests once Bootstrap helpers
    /// land (Ask 4).
    #[tokio::test(flavor = "current_thread")]
    async fn create_attestation_malformed_kind_returns_400() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        // identity-cert kind missing required `function` field.
        let att = NewAttestation {
            attesting: me,
            attested: me,
            properties: vec![(
                entity_ecf::text("kind"),
                entity_ecf::text("identity-cert"),
            )],
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let r = ctx.identity().create_attestation(att).await;
        match r {
            Err(SdkError::BadRequest { status: 400, .. }) => {}
            other => panic!(
                "expected 400 for malformed identity-cert (missing function), got {:?}",
                other
            ),
        }
    }

    /// `supersede_attestation` dispatch probe — the predecessor's
    /// `supersedes` hash references something not in the index, so
    /// the handler returns a structured non-2xx error. Probes that
    /// the wrapper encodes the supersede-request shape correctly
    /// (same as create-request body) and threads it to the identity
    /// handler.
    #[tokio::test(flavor = "current_thread")]
    async fn supersede_attestation_missing_predecessor_dispatches_error() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        let bogus_predecessor = Hash::from_bytes(&[0x00u8; 33]).expect("zero hash");
        let att = NewAttestation {
            attesting: me,
            attested: me,
            properties: vec![
                (entity_ecf::text("kind"), entity_ecf::text("identity-cert")),
                (entity_ecf::text("function"), entity_ecf::text("agent")),
                (entity_ecf::text("mode"), entity_ecf::text("internal")),
            ],
            supersedes: Some(bogus_predecessor),
            not_before: None,
            expires_at: None,
        };
        let r = ctx.identity().supersede_attestation(att).await;
        match r {
            Err(SdkError::NotFound { status: 404, code, .. })
                if code.as_deref() == Some("previous_not_found") => {}
            Ok(ok) => panic!("unexpected success: {:?}", ok.attestation_hash),
            Err(other) => panic!("unexpected error variant: {:?}", other),
        }
    }

    /// `publish_attestation` against a hash that doesn't resolve to a
    /// known attestation returns a non-2xx — the handler can't move
    /// a cert it can't find. Probes: publish-request encodes
    /// attestation_hash + new_mode + optional contact_id; the SDK
    /// computes the destination path for the resource target. We
    /// match the wrapper's error mapping, not handler internals.
    #[tokio::test(flavor = "current_thread")]
    async fn publish_unknown_attestation_returns_error() {
        let ctx = make_ctx();
        let bogus = Hash::from_bytes(&[0x00u8; 33]).expect("zero hash");
        let r = ctx
            .identity()
            .publish_attestation(bogus, PublishMode::Public, None)
            .await;
        match r {
            Err(SdkError::NotFound { status: 404, code, .. })
                if code.as_deref() == Some("cert_not_found") => {}
            Ok(ok) => panic!(
                "unexpected success: hash={:?} new_path={}",
                ok.attestation_hash, ok.new_path
            ),
            Err(other) => panic!("unexpected error variant: {:?}", other),
        }
    }
}
