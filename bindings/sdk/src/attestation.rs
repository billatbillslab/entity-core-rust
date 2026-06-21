//! Typed wrapper for `system/attestation` extension operations.
//!
//! Per `EXTENSION-ATTESTATION.md §6` and `SDK-IDENTITY-INFRASTRUCTURE.md
//! §5.1`. Reached via [`PeerContext::attestation`].
//!
//! ## Scope
//!
//! The attestation handler exposes four operations per
//! `EXTENSION-ATTESTATION §6`: `create`, `supersede`, `revoke`, `verify`.
//! All four are wrapped here.
//!
//! ## Composition role
//!
//! Attestations are the **signed-graph substrate** that identity and
//! quorum compose on (per spec §1.1, SDK-IDENTITY-INFRASTRUCTURE §5).
//! Callers SHOULD use the higher-level identity ops
//! ([`IdentityOps`](crate::identity)) for identity-context attestations
//! rather than calling this wrapper directly — the identity layer
//! enforces per-mode path dispatch and validity rules.
//!
//! Direct `AttestationOps` use is appropriate for **app-defined
//! attestation kinds** (claims outside the identity stack) and for
//! the substrate ops the identity layer itself composes on.
//!
//! ## Antipattern guard
//!
//! Per `GUIDE-SDK-PATTERNS.md §9` — every op routes through the
//! attestation handler (`execute("system/attestation", op, ...)`),
//! never raw `tree:put` into `system/attestation/*`. The handler owns
//! the namespace, validates kind-namespacing (PR-7), and maintains
//! the attestation index.
//!
//! ## Wire shape (path-as-resource)
//!
//! `create`, `supersede`, `revoke` use path-as-resource per V7 §3.2 —
//! the storage path for the new attestation rides in
//! `EXECUTE.resource.targets[0]`. `verify` has no resource (it's a
//! pure lookup-by-hash op).
//!
//! ## Feature gating
//!
//! Available only when `entity-sdk` is built with the `attestation`
//! feature enabled.

use crate::sdk::{PeerContext, SdkError};
use entity_capability::ResourceTarget;
use entity_entity::Entity;
use entity_handler::{ExecuteOptions, HandlerResult};
use entity_hash::Hash;
use entity_types::{
    TYPE_ATTESTATION_CREATE_REQ, TYPE_ATTESTATION_REVOKE_REQ, TYPE_ATTESTATION_SUPERSEDE_REQ,
    TYPE_ATTESTATION_VERIFY_REQ,
};

// ---------------------------------------------------------------------------
// Input types — the public surface for callers constructing attestations.
// Wire shape mirrors `extensions/attestation/src/data.rs::AttestationData`,
// but the SDK does not depend on `entity-attestation` (extension crate
// boundary) so the types are defined locally.
// ---------------------------------------------------------------------------

/// Input payload for [`AttestationOps::create`]. Per
/// `EXTENSION-ATTESTATION §3`.
#[derive(Debug, Clone)]
pub struct NewAttestation {
    /// `system/hash` of the attesting party's identity entity. Per
    /// V7 §3.6 grantee form (33-byte content hash). Use
    /// `PeerContext::identity_hash()` for the local peer's value.
    pub attesting: Hash,
    /// `system/hash` of the entity being attested.
    pub attested: Hash,
    /// Application-defined claim properties, encoded as a CBOR map.
    /// The `kind` field, when present, MUST follow the namespaced
    /// `{ext}/{name}` shape per PR-7 (the handler rejects unnamespaced
    /// kinds other than the universal `revocation` substrate kind).
    pub properties: Vec<(ciborium::Value, ciborium::Value)>,
    /// Predecessor attestation in a supersession chain (§6.1). Set
    /// only for direct-supersedes within the substrate; for chains
    /// authored via the identity layer, use the identity-level
    /// `SupersedeAttestation` instead.
    pub supersedes: Option<Hash>,
    /// Validity window start (unix-ms). `None` = effective immediately.
    pub not_before: Option<u64>,
    /// Validity window end (unix-ms). `None` = never expires.
    pub expires_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Decoded result of `system/attestation:create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationCreateResult {
    /// Hash of the persisted attestation entity.
    pub attestation_hash: Hash,
}

/// Decoded result of `system/attestation:supersede`. Same shape as
/// `create` — both produce a new attestation entity and return its
/// hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationSupersedeResult {
    pub attestation_hash: Hash,
}

/// Decoded result of `system/attestation:revoke`. The revocation is
/// itself an attestation entity (`kind = "revocation"`) targeting the
/// hash to be revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationRevokeResult {
    /// Hash of the revocation attestation just created.
    pub attestation_hash: Hash,
}

/// Decoded result of `system/attestation:verify` per
/// `EXTENSION-ATTESTATION §4.1` + §4.3.
#[derive(Debug, Clone)]
pub struct AttestationVerifyResult {
    /// Single-signature validity plus liveness check.
    pub valid: bool,
    /// Specific failure reason when `valid == false` (e.g.,
    /// `"invalid_signature"`, `"not_live"`, `"attestation_not_indexed"`).
    /// Present only on failures.
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Scope handle
// ---------------------------------------------------------------------------

/// Typed accessor for `system/attestation` operations.
///
/// Created via [`PeerContext::attestation`]. Borrows from the
/// `PeerContext`; futures returned by methods are `'static`.
pub struct AttestationOps<'a> {
    ctx: &'a PeerContext,
}

impl<'a> AttestationOps<'a> {
    pub(crate) fn new(ctx: &'a PeerContext) -> Self {
        Self { ctx }
    }

    /// Create a new attestation at `path`. Per
    /// `EXTENSION-ATTESTATION §6.1`. Generic signed-claim creation;
    /// the handler validates kind-namespacing (PR-7).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn create(
        &self,
        path: impl Into<String>,
        att: NewAttestation,
    ) -> impl std::future::Future<Output = Result<AttestationCreateResult, SdkError>> + Send + 'static
    {
        let params = build_create_request(&att);
        let opts = path_resource_opts(path.into());
        let fut = self.ctx.execute("system/attestation", "create", params, opts);
        async move {
            decode_or_err(fut.await?, "create", |e| {
                decode_attestation_hash_result(e, "create-result")
                    .map(|attestation_hash| AttestationCreateResult { attestation_hash })
            })
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn create(
        &self,
        path: impl Into<String>,
        att: NewAttestation,
    ) -> impl std::future::Future<Output = Result<AttestationCreateResult, SdkError>> + 'static {
        let params = build_create_request(&att);
        let opts = path_resource_opts(path.into());
        let fut = self.ctx.execute("system/attestation", "create", params, opts);
        async move {
            decode_or_err(fut.await?, "create", |e| {
                decode_attestation_hash_result(e, "create-result")
                    .map(|attestation_hash| AttestationCreateResult { attestation_hash })
            })
        }
    }

    /// Create a successor attestation under strict-by-design rules
    /// (§6.2). The handler copies `attesting`/`attested` from the
    /// predecessor; for controller-rotation cases where those fields
    /// legitimately change, use the identity-layer supersede instead.
    ///
    /// `property_overrides` and the validity window are optional; when
    /// `None`, the new attestation inherits the predecessor's values.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn supersede(
        &self,
        path: impl Into<String>,
        previous_hash: Hash,
        property_overrides: Option<Vec<(ciborium::Value, ciborium::Value)>>,
        not_before: Option<u64>,
        expires_at: Option<u64>,
    ) -> impl std::future::Future<Output = Result<AttestationSupersedeResult, SdkError>> + Send + 'static
    {
        let params = build_supersede_request(previous_hash, property_overrides, not_before, expires_at);
        let opts = path_resource_opts(path.into());
        let fut = self.ctx.execute("system/attestation", "supersede", params, opts);
        async move {
            decode_or_err(fut.await?, "supersede", |e| {
                decode_attestation_hash_result(e, "supersede-result")
                    .map(|attestation_hash| AttestationSupersedeResult { attestation_hash })
            })
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn supersede(
        &self,
        path: impl Into<String>,
        previous_hash: Hash,
        property_overrides: Option<Vec<(ciborium::Value, ciborium::Value)>>,
        not_before: Option<u64>,
        expires_at: Option<u64>,
    ) -> impl std::future::Future<Output = Result<AttestationSupersedeResult, SdkError>> + 'static {
        let params = build_supersede_request(previous_hash, property_overrides, not_before, expires_at);
        let opts = path_resource_opts(path.into());
        let fut = self.ctx.execute("system/attestation", "supersede", params, opts);
        async move {
            decode_or_err(fut.await?, "supersede", |e| {
                decode_attestation_hash_result(e, "supersede-result")
                    .map(|attestation_hash| AttestationSupersedeResult { attestation_hash })
            })
        }
    }

    /// Produce a revocation attestation (`kind = "revocation"`)
    /// targeting `target_hash`. Per `EXTENSION-ATTESTATION §6.3` —
    /// convenience wrapper around `create` with the substrate
    /// `revocation` kind. `reason` is informational; pass empty
    /// string for no explicit reason.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn revoke(
        &self,
        path: impl Into<String>,
        target_hash: Hash,
        attesting: Hash,
        reason: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<AttestationRevokeResult, SdkError>> + Send + 'static
    {
        let params = build_revoke_request(target_hash, attesting, &reason.into());
        let opts = path_resource_opts(path.into());
        let fut = self.ctx.execute("system/attestation", "revoke", params, opts);
        async move {
            decode_or_err(fut.await?, "revoke", |e| {
                decode_attestation_hash_result(e, "revoke-result")
                    .map(|attestation_hash| AttestationRevokeResult { attestation_hash })
            })
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn revoke(
        &self,
        path: impl Into<String>,
        target_hash: Hash,
        attesting: Hash,
        reason: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<AttestationRevokeResult, SdkError>> + 'static {
        let params = build_revoke_request(target_hash, attesting, &reason.into());
        let opts = path_resource_opts(path.into());
        let fut = self.ctx.execute("system/attestation", "revoke", params, opts);
        async move {
            decode_or_err(fut.await?, "revoke", |e| {
                decode_attestation_hash_result(e, "revoke-result")
                    .map(|attestation_hash| AttestationRevokeResult { attestation_hash })
            })
        }
    }

    /// Validate single-signature + liveness per §4.1 / §4.3. `as_of`
    /// enables time-traveling validation against historical state.
    /// `verify` has no resource path — the handler looks up the
    /// attestation by hash from its index.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn verify(
        &self,
        attestation_hash: Hash,
        as_of: Option<u64>,
    ) -> impl std::future::Future<Output = Result<AttestationVerifyResult, SdkError>> + Send + 'static
    {
        let params = build_verify_request(attestation_hash, as_of);
        let fut = self
            .ctx
            .execute("system/attestation", "verify", params, ExecuteOptions::default());
        async move { decode_or_err(fut.await?, "verify", decode_verify_result) }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn verify(
        &self,
        attestation_hash: Hash,
        as_of: Option<u64>,
    ) -> impl std::future::Future<Output = Result<AttestationVerifyResult, SdkError>> + 'static {
        let params = build_verify_request(attestation_hash, as_of);
        let fut = self
            .ctx
            .execute("system/attestation", "verify", params, ExecuteOptions::default());
        async move { decode_or_err(fut.await?, "verify", decode_verify_result) }
    }
}

// ---------------------------------------------------------------------------
// Encoders
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

fn build_create_request(att: &NewAttestation) -> Entity {
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
    Entity::new(TYPE_ATTESTATION_CREATE_REQ, data)
        .expect("attestation create-request entity construction is infallible")
}

fn build_supersede_request(
    previous_hash: Hash,
    property_overrides: Option<Vec<(ciborium::Value, ciborium::Value)>>,
    not_before: Option<u64>,
    expires_at: Option<u64>,
) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![(
        entity_ecf::text("previous_hash"),
        ciborium::Value::Bytes(previous_hash.to_bytes().to_vec()),
    )];
    if let Some(ts) = expires_at {
        fields.push((
            entity_ecf::text("expires_at"),
            entity_ecf::integer(ts as i64),
        ));
    }
    if let Some(ts) = not_before {
        fields.push((
            entity_ecf::text("not_before"),
            entity_ecf::integer(ts as i64),
        ));
    }
    if let Some(props) = property_overrides {
        fields.push((entity_ecf::text("properties"), ciborium::Value::Map(props)));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_ATTESTATION_SUPERSEDE_REQ, data)
        .expect("attestation supersede-request entity construction is infallible")
}

fn build_revoke_request(target_hash: Hash, attesting: Hash, reason: &str) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (
            entity_ecf::text("attesting"),
            ciborium::Value::Bytes(attesting.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("target_hash"),
            ciborium::Value::Bytes(target_hash.to_bytes().to_vec()),
        ),
    ];
    if !reason.is_empty() {
        fields.push((entity_ecf::text("reason"), entity_ecf::text(reason)));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_ATTESTATION_REVOKE_REQ, data)
        .expect("attestation revoke-request entity construction is infallible")
}

fn build_verify_request(attestation_hash: Hash, as_of: Option<u64>) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![(
        entity_ecf::text("attestation_hash"),
        ciborium::Value::Bytes(attestation_hash.to_bytes().to_vec()),
    )];
    if let Some(ts) = as_of {
        fields.push((entity_ecf::text("as_of"), entity_ecf::integer(ts as i64)));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_ATTESTATION_VERIFY_REQ, data)
        .expect("attestation verify-request entity construction is infallible")
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

fn decode_or_err<T>(
    result: HandlerResult,
    op: &'static str,
    decode: impl FnOnce(&Entity) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    if let Some(err) = SdkError::from_handler_result(&result, format!("system/attestation:{op}")) {
        return Err(err);
    }
    decode(&result.result)
}

fn decode_attestation_hash_result(entity: &Entity, ctx: &'static str) -> Result<Hash, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode {}: {}", ctx, e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError(format!("{} not a map", ctx)))?;
    for (k, v) in map {
        if k.as_text() == Some("attestation_hash") {
            if let ciborium::Value::Bytes(b) = v {
                if let Ok(h) = Hash::from_bytes(b) {
                    return Ok(h);
                }
            }
        }
    }
    Err(SdkError::HandlerError(format!(
        "{} missing attestation_hash",
        ctx
    )))
}

fn decode_verify_result(entity: &Entity) -> Result<AttestationVerifyResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode verify-result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("verify-result not a map".into()))?;

    let mut valid: Option<bool> = None;
    let mut reason: Option<String> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("valid") => {
                if let ciborium::Value::Bool(b) = v {
                    valid = Some(*b);
                }
            }
            Some("reason") => reason = v.as_text().map(|s| s.to_string()),
            _ => {}
        }
    }
    Ok(AttestationVerifyResult {
        valid: valid
            .ok_or_else(|| SdkError::HandlerError("verify-result missing valid".into()))?,
        reason,
    })
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

    /// `create` writes an attestation entity and returns its hash.
    /// Probes: scope handle reaches the handler, create-request
    /// encodes (attesting + attested + optional fields), result
    /// decodes to a 33-byte `system/hash`. The attestation handler
    /// does not enforce caller_capability at the handler level, so
    /// this dispatch succeeds under the SDK's local-execute path.
    #[tokio::test(flavor = "current_thread")]
    async fn create_writes_attestation_and_returns_hash() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        // Attest "me" attesting "me" — degenerate but legal for the
        // wrapper round-trip test.
        let path = format!("/{}/app/attestations/test-1", ctx.peer_id());
        let att = NewAttestation {
            attesting: me,
            attested: me,
            properties: vec![(
                entity_ecf::text("kind"),
                entity_ecf::text("app/test-claim"),
            )],
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let result = ctx
            .attestation()
            .create(path, att)
            .await
            .expect("create should dispatch");
        // Attestation hash is non-zero (33-byte format-coded hash).
        assert!(
            result.attestation_hash.to_bytes().iter().any(|&b| b != 0),
            "attestation hash should be non-zero"
        );
    }

    /// `supersede` requires a valid predecessor hash. Probes that the
    /// supersede dispatch reaches the handler; with a synthetic
    /// previous_hash that's not in the index, the handler returns
    /// `404 previous_not_found`. Documents the error-path round-trip.
    #[tokio::test(flavor = "current_thread")]
    async fn supersede_missing_predecessor_returns_404() {
        let ctx = make_ctx();
        // Use a non-existent predecessor hash. Construct from a
        // valid 33-byte buffer (format byte + 32-byte digest).
        let bogus_bytes = [0x00u8; 33];
        let bogus = Hash::from_bytes(&bogus_bytes).expect("bogus zero hash construction");
        let path = format!("/{}/app/attestations/test-supersede", ctx.peer_id());

        let result = ctx
            .attestation()
            .supersede(path, bogus, None, None, None)
            .await;
        match result {
            Err(SdkError::NotFound { status: 404, code, .. })
                if code.as_deref() == Some("previous_not_found") => {}
            other => panic!(
                "expected 404 previous_not_found for synthetic predecessor, got {:?}",
                other
            ),
        }
    }

    /// `revoke` creates a revocation attestation and returns its
    /// hash. Probes: revoke-request encodes target_hash + attesting +
    /// reason; result decodes uniformly.
    #[tokio::test(flavor = "current_thread")]
    async fn revoke_returns_revocation_attestation_hash() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        // Create something to revoke first.
        let create_path = format!("/{}/app/attestations/to-revoke", ctx.peer_id());
        let created = ctx
            .attestation()
            .create(
                create_path,
                NewAttestation {
                    attesting: me,
                    attested: me,
                    properties: vec![(
                        entity_ecf::text("kind"),
                        entity_ecf::text("app/test-claim"),
                    )],
                    supersedes: None,
                    not_before: None,
                    expires_at: None,
                },
            )
            .await
            .expect("seed create");

        let revoke_path = format!("/{}/app/attestations/revocation-1", ctx.peer_id());
        let revoked = ctx
            .attestation()
            .revoke(revoke_path, created.attestation_hash, me, "test revocation")
            .await
            .expect("revoke should dispatch");
        assert!(
            revoked.attestation_hash.to_bytes().iter().any(|&b| b != 0),
            "revocation hash should be non-zero"
        );
        assert_ne!(
            revoked.attestation_hash, created.attestation_hash,
            "revocation is a distinct attestation entity"
        );
    }

    /// `verify` on a freshly-created (but unsigned) attestation
    /// returns `valid: false` with `reason: "invalid_signature"`.
    ///
    /// Why: the attestation handler's `create` op stores the entity
    /// but does NOT sign it — signing is the caller's responsibility
    /// per `EXTENSION-ATTESTATION §3` (the substrate is the signed-
    /// *graph*, not the signer). The identity layer composes signing
    /// on top via `system/identity:sign-attestation`. Direct
    /// `AttestationOps::create` callers must produce a separate
    /// `system/signature` entity for `verify` to succeed.
    ///
    /// This test documents that the verify-result decoder handles
    /// the indexed-but-unsigned shape — and that the wrapper does
    /// not silently mask a signature gap.
    #[tokio::test(flavor = "current_thread")]
    async fn verify_indexed_but_unsigned_attestation_returns_invalid_signature() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        let path = format!("/{}/app/attestations/to-verify", ctx.peer_id());
        let created = ctx
            .attestation()
            .create(
                path,
                NewAttestation {
                    attesting: me,
                    attested: me,
                    properties: vec![(
                        entity_ecf::text("kind"),
                        entity_ecf::text("app/test-claim"),
                    )],
                    supersedes: None,
                    not_before: None,
                    expires_at: None,
                },
            )
            .await
            .expect("seed create");

        let v = ctx
            .attestation()
            .verify(created.attestation_hash, None)
            .await
            .expect("verify should dispatch");
        assert!(!v.valid, "unsigned attestation should not verify");
        assert_eq!(
            v.reason.as_deref(),
            Some("invalid_signature"),
            "absent signature is reported as invalid_signature, not as a 404"
        );
    }

    /// `verify` on an unknown hash returns `valid: false` with
    /// `reason = "attestation_not_indexed"`. Documents the error
    /// shape exposed by the wrapper.
    #[tokio::test(flavor = "current_thread")]
    async fn verify_unknown_hash_returns_valid_false() {
        let ctx = make_ctx();
        let bogus = Hash::from_bytes(&[0x00u8; 33]).expect("bogus zero hash construction");
        let v = ctx
            .attestation()
            .verify(bogus, None)
            .await
            .expect("verify should dispatch (returns 200 with valid=false)");
        assert!(!v.valid);
        assert_eq!(v.reason.as_deref(), Some("attestation_not_indexed"));
    }
}
