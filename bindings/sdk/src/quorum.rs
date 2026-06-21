//! Typed wrapper for `system/quorum` extension operations.
//!
//! Per `EXTENSION-QUORUM.md §6` and `SDK-IDENTITY-INFRASTRUCTURE.md
//! §5.2`. Reached via [`PeerContext::quorum`].
//!
//! ## Scope
//!
//! The quorum handler exposes four operations per
//! `EXTENSION-QUORUM §6`: `create`, `update`, `publish`, `verify`.
//! All four are wrapped here.
//!
//! ## Composition role
//!
//! Quorums are the **K-of-N node primitive** that identity composes
//! on (per `SDK-IDENTITY-INFRASTRUCTURE §5.2`). Direct `QuorumOps`
//! use is appropriate for app-defined K-of-N scenarios (governance,
//! transaction signing) **outside** the identity stack; identity-
//! context quorums should be created through
//! [`IdentityOps`](crate::identity) so the identity layer can record
//! the quorum-id in peer-config.
//!
//! ## Antipattern guard
//!
//! Per `GUIDE-SDK-PATTERNS.md §9` — every op routes through the
//! quorum handler (`execute("system/quorum", op, ...)`), never raw
//! `tree:put` into `system/quorum/*`. The handler manages the
//! namespace, validates threshold rules (`1 ≤ K ≤ |signers|`), and
//! maintains the signer-set cache + attestation index.
//!
//! ## Wire shape (path-as-resource)
//!
//! `create`, `update`, `publish` use path-as-resource per V7 §3.2 —
//! the canonical `system/quorum/{quorum_id_hex}` path rides in
//! `EXECUTE.resource.targets[0]`. For `create` the SDK computes
//! `quorum_id` locally (content hash of the same QuorumData shape
//! the handler will produce) so the caller can pass typed inputs
//! rather than pre-formed paths.
//!
//! `verify` has no resource — it's a pure hash-keyed validation op.
//!
//! ## Feature gating
//!
//! Available only when `entity-sdk` is built with the `quorum`
//! feature enabled.

use crate::sdk::{PeerContext, SdkError};
use entity_capability::ResourceTarget;
use entity_entity::Entity;
use entity_handler::{ExecuteOptions, HandlerResult};
use entity_hash::Hash;
use entity_types::{
    TYPE_QUORUM, TYPE_QUORUM_CREATE_REQ, TYPE_QUORUM_PUBLISH_REQ, TYPE_QUORUM_UPDATE_REQ,
    TYPE_QUORUM_VERIFY_REQ,
};

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

/// Input payload for [`QuorumOps::create`]. Mirrors the wire shape of
/// `system/quorum` (`extensions/quorum/src/data.rs::QuorumData`),
/// declared locally to keep the SDK / extension-crate boundary clean.
#[derive(Debug, Clone)]
pub struct NewQuorum {
    /// Constituent identity hashes (the N in K-of-N). Per
    /// `EXTENSION-QUORUM §3.1`.
    pub signers: Vec<Hash>,
    /// Threshold K — number of signatures required. The handler
    /// rejects values outside `1 ≤ K ≤ |signers|` with
    /// `400 invalid_threshold`.
    pub threshold: u64,
    /// Resolver mode identifier per §5.1. `None` defaults to
    /// `"concrete"`; `"identity-resolved"` is registered by the
    /// identity extension at install time (composition entry-point).
    pub signer_resolution: Option<String>,
    /// Optional human-readable label.
    pub name: Option<String>,
    /// Free-form caller-supplied metadata (`primitive/any` map per
    /// §3.1). R-4 byte-fidelity contract: the raw CBOR map flows
    /// through unchanged so the recomputed canonical path matches
    /// the caller's.
    pub metadata: Option<Vec<(ciborium::Value, ciborium::Value)>>,
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Decoded result of `system/quorum:create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumCreateResult {
    /// The canonical quorum identifier — content hash of the
    /// persisted `system/quorum` entity.
    pub quorum_id: Hash,
}

/// Decoded result of `system/quorum:update`. Per §3.2 — the update
/// is itself a quorum-update attestation; the result returns its
/// content hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumUpdateResult {
    /// Content hash of the quorum-update attestation.
    pub update_hash: Hash,
}

/// Decoded result of `system/quorum:publish`. Per §3.3 — the publish
/// is itself a quorum-publish attestation snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumPublishResult {
    /// Content hash of the quorum-publish attestation.
    pub publish_hash: Hash,
}

/// Decoded result of `system/quorum:verify` per §6.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumVerifyResult {
    /// Whether the K-of-N signature check succeeded.
    pub valid: bool,
}

// ---------------------------------------------------------------------------
// Scope handle
// ---------------------------------------------------------------------------

/// Typed accessor for `system/quorum` operations.
///
/// Created via [`PeerContext::quorum`]. Borrows from the
/// `PeerContext`; futures returned by methods are `'static`.
pub struct QuorumOps<'a> {
    ctx: &'a PeerContext,
}

impl<'a> QuorumOps<'a> {
    pub(crate) fn new(ctx: &'a PeerContext) -> Self {
        Self { ctx }
    }

    /// Instantiate a `system/quorum` entity at
    /// `system/quorum/{quorum_id_hex}`. Per `EXTENSION-QUORUM §6.1`.
    /// The SDK computes `quorum_id` locally (content hash of the
    /// same QuorumData shape the handler will produce) to derive the
    /// canonical path — mirrors Go's `Quorum().Create` (see
    /// `workbench-go/entitysdk/quorum.go:52`).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn create(
        &self,
        q: NewQuorum,
    ) -> impl std::future::Future<Output = Result<QuorumCreateResult, SdkError>> + Send + 'static
    {
        let (params, path) = match build_create_request(q) {
            Ok(pair) => pair,
            Err(e) => return future_ready(Err(e)),
        };
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/quorum", "create", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "create", |e| {
                decode_hash_field(e, "quorum_id", "create-result")
                    .map(|quorum_id| QuorumCreateResult { quorum_id })
            })
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn create(
        &self,
        q: NewQuorum,
    ) -> impl std::future::Future<Output = Result<QuorumCreateResult, SdkError>> + 'static {
        let (params, path) = match build_create_request(q) {
            Ok(pair) => pair,
            Err(e) => return future_ready(Err(e)),
        };
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/quorum", "create", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "create", |e| {
                decode_hash_field(e, "quorum_id", "create-result")
                    .map(|quorum_id| QuorumCreateResult { quorum_id })
            })
        })
    }

    /// Produce a quorum-update attestation (§3.2). A self-event signed
    /// by the quorum's current K signers; signature gathering
    /// (collecting K-of-N signatures over the update entity) is the
    /// caller's responsibility. `supersedes` chains successive
    /// updates.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn update(
        &self,
        quorum_id: Hash,
        new_signers: Vec<Hash>,
        new_threshold: u64,
        supersedes: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<QuorumUpdateResult, SdkError>> + Send + 'static
    {
        let params = build_update_request(quorum_id, &new_signers, new_threshold, supersedes);
        let opts = path_resource_opts(path_quorum(&quorum_id));
        let fut = self.ctx.execute("system/quorum", "update", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "update", |e| {
                decode_hash_field(e, "update_hash", "update-result")
                    .map(|update_hash| QuorumUpdateResult { update_hash })
            })
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn update(
        &self,
        quorum_id: Hash,
        new_signers: Vec<Hash>,
        new_threshold: u64,
        supersedes: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<QuorumUpdateResult, SdkError>> + 'static {
        let params = build_update_request(quorum_id, &new_signers, new_threshold, supersedes);
        let opts = path_resource_opts(path_quorum(&quorum_id));
        let fut = self.ctx.execute("system/quorum", "update", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "update", |e| {
                decode_hash_field(e, "update_hash", "update-result")
                    .map(|update_hash| QuorumUpdateResult { update_hash })
            })
        })
    }

    /// Produce a quorum-publish attestation (§3.3) — a snapshot of
    /// the current signer set carrying an optional `published_handle`.
    /// `published_handle` is a generic consumer-extension hook (per
    /// §3.3 v1.2 abstraction); identity uses it to publish the
    /// controller's current handle. `properties` is merged into the
    /// attestation's properties alongside the standard publish fields
    /// (caller MUST NOT include reserved keys `kind`/`signers`/
    /// `threshold`/`published_handle` — handler filters them out).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn publish(
        &self,
        quorum_id: Hash,
        signers: Vec<Hash>,
        threshold: u64,
        published_handle: Option<Hash>,
        supersedes: Option<Hash>,
        properties: Option<Vec<(ciborium::Value, ciborium::Value)>>,
    ) -> impl std::future::Future<Output = Result<QuorumPublishResult, SdkError>> + Send + 'static
    {
        let params = build_publish_request(
            quorum_id,
            &signers,
            threshold,
            published_handle,
            supersedes,
            properties,
        );
        let opts = path_resource_opts(path_quorum(&quorum_id));
        let fut = self.ctx.execute("system/quorum", "publish", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "publish", |e| {
                decode_hash_field(e, "publish_hash", "publish-result")
                    .map(|publish_hash| QuorumPublishResult { publish_hash })
            })
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn publish(
        &self,
        quorum_id: Hash,
        signers: Vec<Hash>,
        threshold: u64,
        published_handle: Option<Hash>,
        supersedes: Option<Hash>,
        properties: Option<Vec<(ciborium::Value, ciborium::Value)>>,
    ) -> impl std::future::Future<Output = Result<QuorumPublishResult, SdkError>> + 'static {
        let params = build_publish_request(
            quorum_id,
            &signers,
            threshold,
            published_handle,
            supersedes,
            properties,
        );
        let opts = path_resource_opts(path_quorum(&quorum_id));
        let fut = self.ctx.execute("system/quorum", "publish", params, opts);
        future_boxed(async move {
            decode_or_err(fut.await?, "publish", |e| {
                decode_hash_field(e, "publish_hash", "publish-result")
                    .map(|publish_hash| QuorumPublishResult { publish_hash })
            })
        })
    }

    /// K-of-N signature validation per §6.4. Walks `entity_hash`'s
    /// signature set, intersects with `quorum_id`'s resolved signer
    /// set, returns whether `≥ K` distinct constituents signed. No
    /// resource path (hash-keyed op).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn verify(
        &self,
        entity_hash: Hash,
        quorum_id: Hash,
    ) -> impl std::future::Future<Output = Result<QuorumVerifyResult, SdkError>> + Send + 'static
    {
        let params = build_verify_request(entity_hash, quorum_id);
        let fut = self
            .ctx
            .execute("system/quorum", "verify", params, ExecuteOptions::default());
        future_boxed(async move { decode_or_err(fut.await?, "verify", decode_verify_result) })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn verify(
        &self,
        entity_hash: Hash,
        quorum_id: Hash,
    ) -> impl std::future::Future<Output = Result<QuorumVerifyResult, SdkError>> + 'static {
        let params = build_verify_request(entity_hash, quorum_id);
        let fut = self
            .ctx
            .execute("system/quorum", "verify", params, ExecuteOptions::default());
        future_boxed(async move { decode_or_err(fut.await?, "verify", decode_verify_result) })
    }
}

// ---------------------------------------------------------------------------
// Path constructor (mirror of extensions/quorum/src/data.rs::path_quorum)
// ---------------------------------------------------------------------------

const QUORUM_STORAGE_PREFIX: &str = "system/quorum/";

fn path_quorum(quorum_id: &Hash) -> String {
    format!("{}{}", QUORUM_STORAGE_PREFIX, quorum_id.to_hex())
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

/// Build a `system/quorum/create-request` entity. Also computes the
/// `quorum_id` locally (content hash of the equivalent `system/quorum`
/// entity body) so the caller doesn't have to thread it through —
/// matches Go's `Quorum().Create` flow.
///
/// R-4 contract: the metadata CBOR map must flow through with byte
/// fidelity; if it doesn't, the recomputed canonical path on the
/// handler diverges from the SDK-computed path and the handler
/// rejects with `resource_target_mismatch`.
fn build_create_request(q: NewQuorum) -> Result<(Entity, String), SdkError> {
    // ECF-sorted body per QuorumData::to_entity (metadata, name,
    // signer_resolution, signers, threshold).
    let body_fields = quorum_body_fields(
        q.metadata.as_ref(),
        q.name.as_deref(),
        q.signer_resolution.as_deref(),
        &q.signers,
        q.threshold,
    );
    // Compute the quorum_id from the canonical system/quorum body.
    let body_data = entity_ecf::to_ecf(&ciborium::Value::Map(body_fields.clone()));
    let q_entity = Entity::new(TYPE_QUORUM, body_data)
        .map_err(|e| SdkError::HandlerError(format!("compute quorum_id: {}", e)))?;
    let quorum_id = q_entity.content_hash;

    // Build the create-request entity — same fields as QuorumData
    // (the handler reads them directly from params).
    let req_data = entity_ecf::to_ecf(&ciborium::Value::Map(body_fields));
    let req_entity = Entity::new(TYPE_QUORUM_CREATE_REQ, req_data)
        .map_err(|e| SdkError::HandlerError(format!("encode create-request: {}", e)))?;

    Ok((req_entity, path_quorum(&quorum_id)))
}

fn quorum_body_fields(
    metadata: Option<&Vec<(ciborium::Value, ciborium::Value)>>,
    name: Option<&str>,
    signer_resolution: Option<&str>,
    signers: &[Hash],
    threshold: u64,
) -> Vec<(ciborium::Value, ciborium::Value)> {
    // ECF order: metadata, name, signer_resolution, signers, threshold.
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    if let Some(m) = metadata {
        fields.push((entity_ecf::text("metadata"), ciborium::Value::Map(m.clone())));
    }
    if let Some(n) = name {
        fields.push((entity_ecf::text("name"), entity_ecf::text(n)));
    }
    if let Some(r) = signer_resolution {
        fields.push((entity_ecf::text("signer_resolution"), entity_ecf::text(r)));
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
    fields
}

fn build_update_request(
    quorum_id: Hash,
    new_signers: &[Hash],
    new_threshold: u64,
    supersedes: Option<Hash>,
) -> Entity {
    // ECF order: new_signers, new_threshold, quorum_id, supersedes.
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            entity_ecf::text("new_signers"),
            ciborium::Value::Array(
                new_signers
                    .iter()
                    .map(|h| ciborium::Value::Bytes(h.to_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (
            entity_ecf::text("new_threshold"),
            entity_ecf::integer(new_threshold as i64),
        ),
        (
            entity_ecf::text("quorum_id"),
            ciborium::Value::Bytes(quorum_id.to_bytes().to_vec()),
        ),
    ];
    if let Some(s) = supersedes {
        fields.push((
            entity_ecf::text("supersedes"),
            ciborium::Value::Bytes(s.to_bytes().to_vec()),
        ));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_QUORUM_UPDATE_REQ, data)
        .expect("update-request entity construction is infallible")
}

fn build_publish_request(
    quorum_id: Hash,
    signers: &[Hash],
    threshold: u64,
    published_handle: Option<Hash>,
    supersedes: Option<Hash>,
    properties: Option<Vec<(ciborium::Value, ciborium::Value)>>,
) -> Entity {
    // ECF order: properties (consumer extension), published_handle,
    // quorum_id, signers, supersedes, threshold.
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    if let Some(ph) = published_handle {
        fields.push((
            entity_ecf::text("published_handle"),
            ciborium::Value::Bytes(ph.to_bytes().to_vec()),
        ));
    }
    if let Some(props) = properties {
        fields.push((
            entity_ecf::text("properties"),
            ciborium::Value::Map(props),
        ));
    }
    fields.push((
        entity_ecf::text("quorum_id"),
        ciborium::Value::Bytes(quorum_id.to_bytes().to_vec()),
    ));
    fields.push((
        entity_ecf::text("signers"),
        ciborium::Value::Array(
            signers
                .iter()
                .map(|h| ciborium::Value::Bytes(h.to_bytes().to_vec()))
                .collect(),
        ),
    ));
    if let Some(s) = supersedes {
        fields.push((
            entity_ecf::text("supersedes"),
            ciborium::Value::Bytes(s.to_bytes().to_vec()),
        ));
    }
    fields.push((
        entity_ecf::text("threshold"),
        entity_ecf::integer(threshold as i64),
    ));
    fields.sort_by(|a, b| {
        a.0.as_text()
            .unwrap_or("")
            .cmp(b.0.as_text().unwrap_or(""))
    });
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_QUORUM_PUBLISH_REQ, data)
        .expect("publish-request entity construction is infallible")
}

fn build_verify_request(entity_hash: Hash, quorum_id: Hash) -> Entity {
    // ECF order: entity_hash, quorum_id.
    let fields: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            entity_ecf::text("entity_hash"),
            ciborium::Value::Bytes(entity_hash.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("quorum_id"),
            ciborium::Value::Bytes(quorum_id.to_bytes().to_vec()),
        ),
    ];
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_QUORUM_VERIFY_REQ, data)
        .expect("verify-request entity construction is infallible")
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

fn decode_or_err<T>(
    result: HandlerResult,
    op: &'static str,
    decode: impl FnOnce(&Entity) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    if let Some(err) = SdkError::from_handler_result(&result, format!("system/quorum:{op}")) {
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

fn decode_verify_result(entity: &Entity) -> Result<QuorumVerifyResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode verify-result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("verify-result not a map".into()))?;
    for (k, v) in map {
        if k.as_text() == Some("valid") {
            if let ciborium::Value::Bool(b) = v {
                return Ok(QuorumVerifyResult { valid: *b });
            }
        }
    }
    Err(SdkError::HandlerError("verify-result missing valid".into()))
}

// ---------------------------------------------------------------------------
// Future helpers — let `create` short-circuit a synchronous encoding
// error without forcing the caller into an extra Result-wrap layer.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
fn future_ready<T: Send + 'static>(
    v: Result<T, SdkError>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SdkError>> + Send + 'static>> {
    Box::pin(async move { v })
}

#[cfg(target_arch = "wasm32")]
fn future_ready<T: 'static>(
    v: Result<T, SdkError>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SdkError>> + 'static>> {
    Box::pin(async move { v })
}

#[cfg(not(target_arch = "wasm32"))]
fn future_boxed<T: Send + 'static, F: std::future::Future<Output = Result<T, SdkError>> + Send + 'static>(
    f: F,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SdkError>> + Send + 'static>> {
    Box::pin(f)
}

#[cfg(target_arch = "wasm32")]
fn future_boxed<T: 'static, F: std::future::Future<Output = Result<T, SdkError>> + 'static>(
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

    /// `create` writes a quorum entity and returns its canonical
    /// quorum_id. Probes: SDK-computed quorum_id matches handler's
    /// recomputed quorum_id (no `resource_target_mismatch`), result
    /// decoder lifts the bytes field to a typed Hash.
    #[tokio::test(flavor = "current_thread")]
    async fn create_writes_quorum_and_returns_id() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        // Single-member 1-of-1 quorum — degenerate but valid.
        let q = NewQuorum {
            signers: vec![me],
            threshold: 1,
            signer_resolution: None,
            name: Some("test-quorum".into()),
            metadata: None,
        };
        let result = ctx
            .quorum()
            .create(q)
            .await
            .expect("create should dispatch");
        assert!(
            result.quorum_id.to_bytes().iter().any(|&b| b != 0),
            "quorum_id should be non-zero"
        );
    }

    /// Invalid threshold (K > N) rejects with 400. Documents
    /// handler-side validation through the wrapper.
    #[tokio::test(flavor = "current_thread")]
    async fn create_threshold_above_signers_rejects_400() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        let q = NewQuorum {
            signers: vec![me],
            threshold: 2,
            signer_resolution: None,
            name: None,
            metadata: None,
        };
        let result = ctx.quorum().create(q).await;
        match result {
            Err(SdkError::BadRequest { status: 400, code, .. })
                if code.as_deref() == Some("invalid_threshold") => {}
            other => panic!("expected 400 invalid_threshold, got {:?}", other),
        }
    }

    /// `update` against an existing quorum returns an update_hash.
    /// Probes: update-request encodes quorum_id + new_signers +
    /// new_threshold; result decoder lifts the update_hash bytes.
    #[tokio::test(flavor = "current_thread")]
    async fn create_then_update_returns_update_hash() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        let created = ctx
            .quorum()
            .create(NewQuorum {
                signers: vec![me],
                threshold: 1,
                signer_resolution: None,
                name: None,
                metadata: None,
            })
            .await
            .expect("seed create");

        let result = ctx
            .quorum()
            .update(created.quorum_id, vec![me], 1, None)
            .await
            .expect("update should dispatch");
        assert!(
            result.update_hash.to_bytes().iter().any(|&b| b != 0),
            "update_hash should be non-zero"
        );
    }

    /// `publish` against an existing quorum returns a publish_hash.
    /// Probes: publish-request encodes the full field set including
    /// optional `published_handle` + `properties`.
    #[tokio::test(flavor = "current_thread")]
    async fn create_then_publish_returns_publish_hash() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        let created = ctx
            .quorum()
            .create(NewQuorum {
                signers: vec![me],
                threshold: 1,
                signer_resolution: None,
                name: None,
                metadata: None,
            })
            .await
            .expect("seed create");

        let result = ctx
            .quorum()
            .publish(created.quorum_id, vec![me], 1, None, None, None)
            .await
            .expect("publish should dispatch");
        assert!(
            result.publish_hash.to_bytes().iter().any(|&b| b != 0),
            "publish_hash should be non-zero"
        );
    }

    /// `verify` against an entity with no K-of-N signatures returns
    /// `valid: false`. Probes: verify-request encodes entity_hash +
    /// quorum_id; result decoder lifts the bool.
    #[tokio::test(flavor = "current_thread")]
    async fn verify_unsigned_entity_returns_invalid() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        let created = ctx
            .quorum()
            .create(NewQuorum {
                signers: vec![me],
                threshold: 1,
                signer_resolution: None,
                name: None,
                metadata: None,
            })
            .await
            .expect("seed create");

        // verify a synthetic hash that wasn't signed by any quorum
        // constituent.
        let target = Hash::from_bytes(&[0x00u8; 33]).expect("zero hash");
        let v = ctx
            .quorum()
            .verify(target, created.quorum_id)
            .await
            .expect("verify should dispatch");
        assert!(
            !v.valid,
            "unsigned target should not pass K-of-N verification"
        );
    }
}
