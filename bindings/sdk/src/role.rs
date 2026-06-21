//! Typed wrapper for `system/role` extension operations.
//!
//! Per `SDK-EXTENSION-OPERATIONS.md §13` and `EXTENSION-ROLE.md` v2.0
//! (with Amendments 1+2). Reached via [`PeerContext::role`].
//!
//! ## Scope
//!
//! The role handler exposes seven operations per `EXTENSION-ROLE §4.1`:
//! `define`, `assign`, `unassign`, `exclude`, `unexclude`, `re-derive`,
//! `delegate`. All seven are wrapped here.
//!
//! ## Antipattern guard (load-bearing)
//!
//! Per `GUIDE-SDK-PATTERNS.md §9` — the kernel-vs-handler antipattern.
//! Every op in this module goes through the role handler entrypoint
//! (`execute("system/role", op, ...)`), NEVER raw `tree:put` into
//! `system/role/*`. The role extension manages the namespace; bypassing
//! the handler skips RL1/RL2 authorization, exclusion checks, derived-
//! token issuance, and the re-derive cascade.
//!
//! This is the surface Godot γ.4.2 hit and got pulled back from.
//!
//! ## Wire shape (path-as-resource)
//!
//! Per `EXTENSION-ROLE §4.2`, every op carries its target tree path in
//! `EXECUTE.resource.targets[0]`. Params carry only the role-name
//! selector (or are empty for unassign/exclude/unexclude). This module
//! constructs paths internally — callers pass typed `(context, role,
//! peer_hash)` triples, not pre-formed strings.
//!
//! ## Feature gating
//!
//! Available only when `entity-sdk` is built with the `role` feature
//! enabled.
//!
//! ## Caller capability — owner self-cap (SDK-OPERATIONS §11.2A)
//!
//! The role handler MUSTs `caller_capability` for the four RL2-bearing
//! ops (`define` / `assign` / `re-derive` / `delegate` per §4.3 + §4.2).
//! The SDK stamps a wildcard owner self-cap onto every local L1
//! dispatch (see `PeerContextBuilder::build` → `mint_owner_self_cap`),
//! matching Go SDK's `mintOwnerSelfCap` (`workbench-go/entitysdk/app.go`).
//! This is the open-grants-mode posture per SDK-OPERATIONS §11.2A —
//! when kernel-side grant enforcement lands (Cut 2+), the owner cap
//! becomes opt-in / overridable rather than the default.

use crate::sdk::{PeerContext, SdkError};
use entity_capability::{decode_grant_entry, encode_grant_entry, GrantEntry, ResourceTarget};
use entity_entity::Entity;
use entity_handler::{ExecuteOptions, HandlerResult};
use entity_hash::Hash;
use entity_types::{
    TYPE_ROLE_ASSIGN_REQUEST, TYPE_ROLE_DEFINE_REQUEST, TYPE_ROLE_DELEGATE_REQUEST,
    TYPE_ROLE_RE_DERIVE_REQUEST,
};

// ---------------------------------------------------------------------------
// Result types — decoded from each handler's result entity.
// ---------------------------------------------------------------------------

/// Decoded result of `system/role:define`. Per `EXTENSION-ROLE §4.2`.
#[derive(Debug, Clone)]
pub struct RoleDefineResult {
    /// The role definition path as authored. The handler preserves
    /// the caller's path form (peer-relative or peer-qualified) per
    /// V7's canonicalization-on-input model — do not re-canonicalize.
    pub role_path: String,
    /// Count of (peer, role) assignments re-derived as a cascade of
    /// this mutation. Absent on first define of a role.
    pub re_derived_count: Option<u64>,
}

/// Decoded result of `system/role:assign`. Per `EXTENSION-ROLE §4.2`.
#[derive(Debug, Clone)]
pub struct RoleAssignResult {
    pub assignment_path: String,
    /// Hashes of capability tokens issued for the assignee.
    pub derived_tokens: Vec<Hash>,
}

/// Decoded result of `system/role:unassign`. Per `EXTENSION-ROLE §4.2`.
///
/// Note: spec manifest at §4.1 lists `output_type: system/protocol/status`
/// but the handler returns a richer `system/role/unassign-result` with
/// `assignment_path` + `revoked_token_hashes`. Decoded shape matches the
/// handler (the wire-truth).
#[derive(Debug, Clone)]
pub struct RoleUnassignResult {
    pub assignment_path: String,
    pub revoked_token_hashes: Vec<Hash>,
}

/// Decoded result of `system/role:exclude`. Per `EXTENSION-ROLE §4.2`.
#[derive(Debug, Clone)]
pub struct RoleExcludeResult {
    pub exclusion_path: String,
    /// Token hashes revoked by the layer-1 sweep (§6.1).
    pub revoked_token_hashes: Vec<Hash>,
}

/// Decoded result of `system/role:unexclude`. Per `EXTENSION-ROLE §4.2`.
///
/// Same spec-vs-handler divergence as unassign: manifest lists
/// `system/protocol/status` but handler returns `{exclusion_path}`.
#[derive(Debug, Clone)]
pub struct RoleUnexcludeResult {
    pub exclusion_path: String,
}

/// Decoded result of `system/role:re-derive`. Per `EXTENSION-ROLE §4.2`,
/// §5.5 IA9 lifecycle.
#[derive(Debug, Clone)]
pub struct RoleReDeriveResult {
    /// Successfully re-derived assignments. Empty-set re-derive (zero
    /// assignments) returns 200 with count=0; that's a valid no-op
    /// cascade per §4.2.
    pub re_derived_count: u64,
    pub revoked_token_hashes: Vec<Hash>,
    pub new_token_hashes: Vec<Hash>,
    /// Assignees whose per-peer RL2 check failed mid-cascade (SI-15
    /// v1.6); they retain `T_old`. Caller can recover the assignment
    /// by reading `system/role/{context}/assignment/{hex(grantee)}/`.
    pub skipped_grantees: Vec<Hash>,
}

/// Decoded result of `system/role:delegate`. Per `EXTENSION-ROLE §4.2`,
/// §5.6 IA22 member-to-member lifecycle.
#[derive(Debug, Clone)]
pub struct RoleDelegateResult {
    pub delegation_token_hash: Hash,
}

// ---------------------------------------------------------------------------
// Scope handle
// ---------------------------------------------------------------------------

/// Typed accessor for `system/role` operations.
///
/// Created via [`PeerContext::role`]. Borrows from the `PeerContext`;
/// futures returned by methods are `'static`.
pub struct RoleOps<'a> {
    ctx: &'a PeerContext,
}

impl<'a> RoleOps<'a> {
    pub(crate) fn new(ctx: &'a PeerContext) -> Self {
        Self { ctx }
    }

    // -----------------------------------------------------------------------
    // define (per IA11)
    // -----------------------------------------------------------------------

    /// Write or mutate a role definition at
    /// `system/role/{context}/{role_name}`. Triggers a re-derive cascade
    /// when the role already exists (§5.5 IA11). `metadata` is opaque
    /// CBOR — pass `None` for a role with no metadata.
    ///
    /// Per `EXTENSION-ROLE §4.2`. Routed through the role handler — never
    /// raw `tree:put` (per `GUIDE-SDK-PATTERNS §9`).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn define(
        &self,
        context: impl Into<String>,
        role_name: impl Into<String>,
        grants: Vec<GrantEntry>,
        metadata: Option<ciborium::Value>,
    ) -> impl std::future::Future<Output = Result<RoleDefineResult, SdkError>> + Send + 'static
    {
        let path = path_role_definition(&context.into(), &role_name.into());
        let params = build_define_request(&grants, metadata);
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/role", "define", params, opts);
        async move { decode_or_err(fut.await?, "define", decode_define_result) }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn define(
        &self,
        context: impl Into<String>,
        role_name: impl Into<String>,
        grants: Vec<GrantEntry>,
        metadata: Option<ciborium::Value>,
    ) -> impl std::future::Future<Output = Result<RoleDefineResult, SdkError>> + 'static {
        let path = path_role_definition(&context.into(), &role_name.into());
        let params = build_define_request(&grants, metadata);
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/role", "define", params, opts);
        async move { decode_or_err(fut.await?, "define", decode_define_result) }
    }

    // -----------------------------------------------------------------------
    // assign
    // -----------------------------------------------------------------------

    /// Bind `peer_hash` to `role_name` within `context` and issue role-
    /// derived capability tokens (§4.3 + §5.1). The minted cap inherits
    /// `MIN_DEFINED(parent, role.ttl, caller_cap)` per §5.3 v2.0.
    ///
    /// `peer_hash` is the assignee's identity-entity `system/hash`
    /// (V7 §3.6 grantee convention).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn assign(
        &self,
        context: impl Into<String>,
        peer_hash: Hash,
        role_name: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<RoleAssignResult, SdkError>> + Send + 'static
    {
        let role_name = role_name.into();
        let path = path_role_assignment(&context.into(), &peer_segment_from_hash(&peer_hash), &role_name);
        let params = build_assign_request(&role_name);
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/role", "assign", params, opts);
        async move { decode_or_err(fut.await?, "assign", decode_assign_result) }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn assign(
        &self,
        context: impl Into<String>,
        peer_hash: Hash,
        role_name: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<RoleAssignResult, SdkError>> + 'static {
        let role_name = role_name.into();
        let path = path_role_assignment(&context.into(), &peer_segment_from_hash(&peer_hash), &role_name);
        let params = build_assign_request(&role_name);
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/role", "assign", params, opts);
        async move { decode_or_err(fut.await?, "assign", decode_assign_result) }
    }

    // -----------------------------------------------------------------------
    // unassign
    // -----------------------------------------------------------------------

    /// Remove an assignment for `(peer_hash, role_name)` in `context`.
    /// When `role_name` is `None`, drops the trailing role segment per
    /// §4.4 — removing every role for the peer in the context.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn unassign(
        &self,
        context: impl Into<String>,
        peer_hash: Hash,
        role_name: Option<&str>,
    ) -> impl std::future::Future<Output = Result<RoleUnassignResult, SdkError>> + Send + 'static
    {
        let seg = peer_segment_from_hash(&peer_hash);
        let path = match role_name {
            Some(r) => path_role_assignment(&context.into(), &seg, r),
            None => prefix_role_assignment_peer(&context.into(), &seg),
        };
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/role", "unassign", empty_params(), opts);
        async move { decode_or_err(fut.await?, "unassign", decode_unassign_result) }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn unassign(
        &self,
        context: impl Into<String>,
        peer_hash: Hash,
        role_name: Option<&str>,
    ) -> impl std::future::Future<Output = Result<RoleUnassignResult, SdkError>> + 'static {
        let seg = peer_segment_from_hash(&peer_hash);
        let path = match role_name {
            Some(r) => path_role_assignment(&context.into(), &seg, r),
            None => prefix_role_assignment_peer(&context.into(), &seg),
        };
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/role", "unassign", empty_params(), opts);
        async move { decode_or_err(fut.await?, "unassign", decode_unassign_result) }
    }

    // -----------------------------------------------------------------------
    // exclude
    // -----------------------------------------------------------------------

    /// Write an exclusion for `peer_hash` in `context` and trigger the
    /// layer-1 sweep (§6.1) — fleet-wide revocation of the peer's role-
    /// derived caps within this context.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn exclude(
        &self,
        context: impl Into<String>,
        peer_hash: Hash,
    ) -> impl std::future::Future<Output = Result<RoleExcludeResult, SdkError>> + Send + 'static
    {
        let path = path_role_exclusion(&context.into(), &peer_segment_from_hash(&peer_hash));
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/role", "exclude", empty_params(), opts);
        async move { decode_or_err(fut.await?, "exclude", decode_exclude_result) }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn exclude(
        &self,
        context: impl Into<String>,
        peer_hash: Hash,
    ) -> impl std::future::Future<Output = Result<RoleExcludeResult, SdkError>> + 'static {
        let path = path_role_exclusion(&context.into(), &peer_segment_from_hash(&peer_hash));
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/role", "exclude", empty_params(), opts);
        async move { decode_or_err(fut.await?, "exclude", decode_exclude_result) }
    }

    // -----------------------------------------------------------------------
    // unexclude
    // -----------------------------------------------------------------------

    /// Remove the exclusion entity for `peer_hash` in `context`. Per
    /// §6.4 this does NOT auto-restore role-derived caps — re-assignment
    /// is required.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn unexclude(
        &self,
        context: impl Into<String>,
        peer_hash: Hash,
    ) -> impl std::future::Future<Output = Result<RoleUnexcludeResult, SdkError>> + Send + 'static
    {
        let path = path_role_exclusion(&context.into(), &peer_segment_from_hash(&peer_hash));
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/role", "unexclude", empty_params(), opts);
        async move { decode_or_err(fut.await?, "unexclude", decode_unexclude_result) }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn unexclude(
        &self,
        context: impl Into<String>,
        peer_hash: Hash,
    ) -> impl std::future::Future<Output = Result<RoleUnexcludeResult, SdkError>> + 'static {
        let path = path_role_exclusion(&context.into(), &peer_segment_from_hash(&peer_hash));
        let opts = path_resource_opts(path);
        let fut = self
            .ctx
            .execute("system/role", "unexclude", empty_params(), opts);
        async move { decode_or_err(fut.await?, "unexclude", decode_unexclude_result) }
    }

    // -----------------------------------------------------------------------
    // re-derive (per R5)
    // -----------------------------------------------------------------------

    /// Walk every assignment of `role_name` in `context` and re-issue
    /// role-derived caps (§5.5 IA9). Per SI-15, assignees that fail
    /// RL2 mid-cascade appear in `skipped_grantees` rather than aborting
    /// the cascade.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn re_derive(
        &self,
        context: impl Into<String>,
        role_name: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<RoleReDeriveResult, SdkError>> + Send + 'static
    {
        let role_name = role_name.into();
        let path = path_role_definition(&context.into(), &role_name);
        let params = build_re_derive_request(&role_name);
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/role", "re-derive", params, opts);
        async move { decode_or_err(fut.await?, "re-derive", decode_re_derive_result) }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn re_derive(
        &self,
        context: impl Into<String>,
        role_name: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<RoleReDeriveResult, SdkError>> + 'static {
        let role_name = role_name.into();
        let path = path_role_definition(&context.into(), &role_name);
        let params = build_re_derive_request(&role_name);
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/role", "re-derive", params, opts);
        async move { decode_or_err(fut.await?, "re-derive", decode_re_derive_result) }
    }

    // -----------------------------------------------------------------------
    // delegate (per IA22)
    // -----------------------------------------------------------------------

    /// Member-to-member delegation (§5.6). The local peer (the delegator
    /// per SI-19) delegates a role they hold to `delegate`. `scope` MUST
    /// be a subset of the delegator's grants for the role and MUST NOT
    /// contain template variables (§5.6 step 3a, SI-20). `expires_at`
    /// is optional (no bound when `None`).
    ///
    /// SI-19: this op MUST run on the delegator's own runtime peer —
    /// the handler checks `ctx.author == self.identity_hash`. There is
    /// no `delegator` field on the request body (SI-21).
    ///
    /// The resource target is the delegator's assignment path; the
    /// handler synthesizes the role-derived storage path internally.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn delegate(
        &self,
        context: impl Into<String>,
        role_name: impl Into<String>,
        delegator: Hash,
        delegate: Hash,
        scope: Vec<GrantEntry>,
        expires_at: Option<u64>,
    ) -> impl std::future::Future<Output = Result<RoleDelegateResult, SdkError>> + Send + 'static
    {
        let context = context.into();
        let role_name = role_name.into();
        let path = path_role_assignment(&context, &peer_segment_from_hash(&delegator), &role_name);
        let params = build_delegate_request(&context, &role_name, delegate, &scope, expires_at);
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/role", "delegate", params, opts);
        async move { decode_or_err(fut.await?, "delegate", decode_delegate_result) }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn delegate(
        &self,
        context: impl Into<String>,
        role_name: impl Into<String>,
        delegator: Hash,
        delegate: Hash,
        scope: Vec<GrantEntry>,
        expires_at: Option<u64>,
    ) -> impl std::future::Future<Output = Result<RoleDelegateResult, SdkError>> + 'static {
        let context = context.into();
        let role_name = role_name.into();
        let path = path_role_assignment(&context, &peer_segment_from_hash(&delegator), &role_name);
        let params = build_delegate_request(&context, &role_name, delegate, &scope, expires_at);
        let opts = path_resource_opts(path);
        let fut = self.ctx.execute("system/role", "delegate", params, opts);
        async move { decode_or_err(fut.await?, "delegate", decode_delegate_result) }
    }
}

// ---------------------------------------------------------------------------
// Path constructors (mirror extensions/role/src/paths.rs, kept local to
// preserve the SDK / extension-crate boundary — sdk does not import
// entity-role).
// ---------------------------------------------------------------------------

const ROLE_PREFIX: &str = "system/role/";

fn path_role_definition(context: &str, role_name: &str) -> String {
    format!("{}{}/{}", ROLE_PREFIX, context, role_name)
}

fn path_role_assignment(context: &str, peer_id_hex: &str, role_name: &str) -> String {
    format!(
        "{}{}/assignment/{}/{}",
        ROLE_PREFIX, context, peer_id_hex, role_name
    )
}

fn prefix_role_assignment_peer(context: &str, peer_id_hex: &str) -> String {
    format!("{}{}/assignment/{}/", ROLE_PREFIX, context, peer_id_hex)
}

fn path_role_exclusion(context: &str, peer_id_hex: &str) -> String {
    format!("{}{}/excluded/{}", ROLE_PREFIX, context, peer_id_hex)
}

/// Encode a `system/hash` as the lowercase-hex segment used in role
/// paths (SI-1 v1.6). 33 raw bytes → 66 hex characters.
fn peer_segment_from_hash(h: &Hash) -> String {
    let bytes = h.to_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// ---------------------------------------------------------------------------
// Request encoders
// ---------------------------------------------------------------------------

fn empty_params() -> Entity {
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(Vec::new()));
    Entity::new("primitive/any", data)
        .expect("empty primitive/any entity construction is infallible")
}

fn path_resource_opts(path: String) -> ExecuteOptions {
    ExecuteOptions {
        resource: Some(ResourceTarget {
            targets: vec![path],
            exclude: vec![],
        }),
        ..Default::default()
    }
}

fn build_define_request(grants: &[GrantEntry], metadata: Option<ciborium::Value>) -> Entity {
    let grants_val = ciborium::Value::Array(grants.iter().map(encode_grant_entry).collect());
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> =
        vec![(entity_ecf::text("grants"), grants_val)];
    if let Some(meta) = metadata {
        fields.push((entity_ecf::text("metadata"), meta));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_ROLE_DEFINE_REQUEST, data)
        .expect("define-request entity construction is infallible")
}

fn build_assign_request(role_name: &str) -> Entity {
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(vec![(
        entity_ecf::text("role"),
        entity_ecf::text(role_name),
    )]));
    Entity::new(TYPE_ROLE_ASSIGN_REQUEST, data)
        .expect("assign-request entity construction is infallible")
}

fn build_re_derive_request(role_name: &str) -> Entity {
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(vec![(
        entity_ecf::text("role"),
        entity_ecf::text(role_name),
    )]));
    Entity::new(TYPE_ROLE_RE_DERIVE_REQUEST, data)
        .expect("re-derive-request entity construction is infallible")
}

fn build_delegate_request(
    context: &str,
    role_name: &str,
    delegate: Hash,
    scope: &[GrantEntry],
    expires_at: Option<u64>,
) -> Entity {
    let scope_val = ciborium::Value::Array(scope.iter().map(encode_grant_entry).collect());
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (entity_ecf::text("context"), entity_ecf::text(context)),
        (
            entity_ecf::text("delegate"),
            ciborium::Value::Bytes(delegate.to_bytes().to_vec()),
        ),
        (entity_ecf::text("role"), entity_ecf::text(role_name)),
        (entity_ecf::text("scope"), scope_val),
    ];
    if let Some(ts) = expires_at {
        fields.push((
            entity_ecf::text("expires_at"),
            entity_ecf::integer(ts as i64),
        ));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new(TYPE_ROLE_DELEGATE_REQUEST, data)
        .expect("delegate-request entity construction is infallible")
}

// ---------------------------------------------------------------------------
// Result decoders
// ---------------------------------------------------------------------------

fn decode_or_err<T>(
    result: HandlerResult,
    op: &'static str,
    decode: impl FnOnce(&Entity) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    if let Some(err) = SdkError::from_handler_result(&result, format!("system/role:{op}")) {
        return Err(err);
    }
    decode(&result.result)
}

fn read_map(entity: &Entity, ctx: &'static str) -> Result<Vec<(ciborium::Value, ciborium::Value)>, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode {}: {}", ctx, e)))?;
    match val {
        ciborium::Value::Map(m) => Ok(m),
        _ => Err(SdkError::HandlerError(format!("{} not a map", ctx))),
    }
}

fn decode_text(v: &ciborium::Value) -> Option<String> {
    v.as_text().map(|s| s.to_string())
}

fn decode_u64(v: &ciborium::Value) -> Option<u64> {
    if let ciborium::Value::Integer(i) = v {
        let signed: i128 = (*i).into();
        if signed >= 0 {
            return Some(signed as u64);
        }
    }
    None
}

fn decode_hash_array(v: &ciborium::Value) -> Vec<Hash> {
    let arr = match v {
        ciborium::Value::Array(a) => a,
        _ => return Vec::new(),
    };
    arr.iter()
        .filter_map(|item| {
            if let ciborium::Value::Bytes(b) = item {
                Hash::from_bytes(b).ok()
            } else {
                None
            }
        })
        .collect()
}

fn decode_define_result(entity: &Entity) -> Result<RoleDefineResult, SdkError> {
    let map = read_map(entity, "define-result")?;
    let mut role_path: Option<String> = None;
    let mut re_derived_count: Option<u64> = None;
    for (k, v) in &map {
        match k.as_text() {
            Some("role_path") => role_path = decode_text(v),
            Some("re_derived_count") => re_derived_count = decode_u64(v),
            _ => {}
        }
    }
    Ok(RoleDefineResult {
        role_path: role_path
            .ok_or_else(|| SdkError::HandlerError("define-result missing role_path".into()))?,
        re_derived_count,
    })
}

fn decode_assign_result(entity: &Entity) -> Result<RoleAssignResult, SdkError> {
    let map = read_map(entity, "assign-result")?;
    let mut assignment_path: Option<String> = None;
    let mut derived_tokens: Vec<Hash> = Vec::new();
    for (k, v) in &map {
        match k.as_text() {
            Some("assignment_path") => assignment_path = decode_text(v),
            Some("derived_tokens") => derived_tokens = decode_hash_array(v),
            _ => {}
        }
    }
    Ok(RoleAssignResult {
        assignment_path: assignment_path
            .ok_or_else(|| SdkError::HandlerError("assign-result missing assignment_path".into()))?,
        derived_tokens,
    })
}

fn decode_unassign_result(entity: &Entity) -> Result<RoleUnassignResult, SdkError> {
    let map = read_map(entity, "unassign-result")?;
    let mut assignment_path: Option<String> = None;
    let mut revoked_token_hashes: Vec<Hash> = Vec::new();
    for (k, v) in &map {
        match k.as_text() {
            Some("assignment_path") => assignment_path = decode_text(v),
            Some("revoked_token_hashes") => revoked_token_hashes = decode_hash_array(v),
            _ => {}
        }
    }
    Ok(RoleUnassignResult {
        assignment_path: assignment_path
            .ok_or_else(|| SdkError::HandlerError("unassign-result missing assignment_path".into()))?,
        revoked_token_hashes,
    })
}

fn decode_exclude_result(entity: &Entity) -> Result<RoleExcludeResult, SdkError> {
    let map = read_map(entity, "exclude-result")?;
    let mut exclusion_path: Option<String> = None;
    let mut revoked_token_hashes: Vec<Hash> = Vec::new();
    for (k, v) in &map {
        match k.as_text() {
            Some("exclusion_path") => exclusion_path = decode_text(v),
            Some("revoked_token_hashes") => revoked_token_hashes = decode_hash_array(v),
            _ => {}
        }
    }
    Ok(RoleExcludeResult {
        exclusion_path: exclusion_path
            .ok_or_else(|| SdkError::HandlerError("exclude-result missing exclusion_path".into()))?,
        revoked_token_hashes,
    })
}

fn decode_unexclude_result(entity: &Entity) -> Result<RoleUnexcludeResult, SdkError> {
    let map = read_map(entity, "unexclude-result")?;
    let mut exclusion_path: Option<String> = None;
    for (k, v) in &map {
        if k.as_text() == Some("exclusion_path") {
            exclusion_path = decode_text(v);
        }
    }
    Ok(RoleUnexcludeResult {
        exclusion_path: exclusion_path
            .ok_or_else(|| SdkError::HandlerError("unexclude-result missing exclusion_path".into()))?,
    })
}

fn decode_re_derive_result(entity: &Entity) -> Result<RoleReDeriveResult, SdkError> {
    let map = read_map(entity, "re-derive-result")?;
    let mut re_derived_count: u64 = 0;
    let mut revoked_token_hashes: Vec<Hash> = Vec::new();
    let mut new_token_hashes: Vec<Hash> = Vec::new();
    let mut skipped_grantees: Vec<Hash> = Vec::new();
    for (k, v) in &map {
        match k.as_text() {
            Some("re_derived_count") => {
                if let Some(n) = decode_u64(v) {
                    re_derived_count = n;
                }
            }
            Some("revoked_token_hashes") => revoked_token_hashes = decode_hash_array(v),
            Some("new_token_hashes") => new_token_hashes = decode_hash_array(v),
            Some("skipped_grantees") => skipped_grantees = decode_hash_array(v),
            _ => {}
        }
    }
    Ok(RoleReDeriveResult {
        re_derived_count,
        revoked_token_hashes,
        new_token_hashes,
        skipped_grantees,
    })
}

fn decode_delegate_result(entity: &Entity) -> Result<RoleDelegateResult, SdkError> {
    let map = read_map(entity, "delegate-result")?;
    for (k, v) in &map {
        if k.as_text() == Some("delegation_token_hash") {
            if let ciborium::Value::Bytes(b) = v {
                if let Ok(h) = Hash::from_bytes(b) {
                    return Ok(RoleDelegateResult {
                        delegation_token_hash: h,
                    });
                }
            }
        }
    }
    Err(SdkError::HandlerError(
        "delegate-result missing delegation_token_hash".into(),
    ))
}

// Re-exported here so the unused-import lint doesn't trip when the
// decoders are added incrementally. (decode_grant_entry is currently
// unused by the wrapper — every op encodes grants but none parse
// grants out of a response — but it's part of the GrantEntry codec
// pair and exposing both keeps future-result-decoders ergonomic.)
#[allow(dead_code)]
fn _grant_codec_pair_is_part_of_the_public_capability_surface(v: &ciborium::Value) -> Option<GrantEntry> {
    decode_grant_entry(v).ok()
}

// ---------------------------------------------------------------------------
// Tests — minimal dispatch probes. The role extension has its own
// 1000-line test suite covering RL1/RL2/sweep semantics; these only
// verify the wrapper threads params through and decodes the wire shape
// correctly.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::PeerContextBuilder;
    use entity_capability::{IdScope, PathScope};

    fn make_ctx() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    fn sample_grants() -> Vec<GrantEntry> {
        vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["app/notes/*".into()]),
            operations: IdScope::all(),
            peers: None,
            constraints: None,
            allowances: None,
        }]
    }

    /// `define` writes a new role definition and echoes the
    /// canonicalized role_path. Probes: scope handle reaches the role
    /// handler, define-request encodes (grants array + optional
    /// metadata), define-result decodes (re_derived_count absent on
    /// first define since no cascade). Owner self-cap (SDK §11.2A)
    /// satisfies RL2.
    #[tokio::test(flavor = "current_thread")]
    async fn define_first_time_returns_role_path() {
        let ctx = make_ctx();
        let result = ctx
            .role()
            .define("group/team-alpha", "editor", sample_grants(), None)
            .await
            .expect("define should dispatch");
        assert!(
            result.role_path.contains("group/team-alpha/editor"),
            "role_path should echo the definition path, got `{}`",
            result.role_path
        );
        assert!(
            result.re_derived_count.is_none() || result.re_derived_count == Some(0),
            "first define has no cascade — got {:?}",
            result.re_derived_count
        );
    }

    /// `assign` after `define` returns an assignment_path and a
    /// (possibly empty) derived_tokens array. Probes: handler accepts
    /// the local peer's identity hash as the grantee; decoder handles
    /// the optional `derived_tokens` field.
    #[tokio::test(flavor = "current_thread")]
    async fn define_then_assign_returns_assignment_path() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        ctx.role()
            .define("group/alpha", "viewer", sample_grants(), None)
            .await
            .expect("define");
        let result = ctx
            .role()
            .assign("group/alpha", me, "viewer")
            .await
            .expect("assign should dispatch");
        assert!(
            result.assignment_path.contains("group/alpha/assignment/"),
            "assignment_path malformed: {}",
            result.assignment_path
        );
    }

    /// `unassign` is one of the three ops that does NOT enforce RL2
    /// at the handler (§4.4) — so the local self-execute path
    /// succeeds. Verifies the prefix-form path (no trailing role
    /// segment) and the empty-params request shape.
    #[tokio::test(flavor = "current_thread")]
    async fn unassign_all_roles_for_peer_dispatches() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        let result = ctx
            .role()
            .unassign("group/beta", me, None)
            .await
            .expect("unassign-all should dispatch (no RL2 on unassign)");
        assert!(
            result.assignment_path.contains("group/beta/assignment/"),
            "got {}",
            result.assignment_path
        );
    }

    /// `exclude` writes an exclusion entity. Probes: exclude-result
    /// decodes; revoked_token_hashes is empty when no role-derived
    /// caps exist for the peer.
    #[tokio::test(flavor = "current_thread")]
    async fn exclude_fresh_peer_returns_exclusion_path() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        let result = ctx
            .role()
            .exclude("group/gamma", me)
            .await
            .expect("exclude should dispatch");
        assert!(
            result.exclusion_path.contains("group/gamma/excluded/"),
            "got {}",
            result.exclusion_path
        );
    }

    /// `unexclude` removes an exclusion entity. Probes: round-trips
    /// the unexclude-result `{exclusion_path}` shape.
    #[tokio::test(flavor = "current_thread")]
    async fn exclude_then_unexclude_dispatches() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        ctx.role().exclude("group/delta", me).await.expect("exclude");

        let result = ctx
            .role()
            .unexclude("group/delta", me)
            .await
            .expect("unexclude should dispatch");
        assert!(
            result.exclusion_path.contains("group/delta/excluded/"),
            "got {}",
            result.exclusion_path
        );
    }

    /// `re-derive` on an empty assignment set returns count=0 per §4.2
    /// "empty-set re-derive is a valid no-op cascade".
    #[tokio::test(flavor = "current_thread")]
    async fn re_derive_empty_context_returns_zero_count() {
        let ctx = make_ctx();
        ctx.role()
            .define("group/epsilon", "viewer", sample_grants(), None)
            .await
            .expect("define");

        let result = ctx
            .role()
            .re_derive("group/epsilon", "viewer")
            .await
            .expect("re-derive should dispatch");
        assert_eq!(result.re_derived_count, 0);
        assert!(result.revoked_token_hashes.is_empty());
        assert!(result.new_token_hashes.is_empty());
        assert!(result.skipped_grantees.is_empty());
    }

    /// `delegate` against the local peer as delegator. SI-19 requires
    /// `ctx.author == identity_hash`. Probes: delegate-request encodes
    /// scope + delegate + context + role + expires_at; the wrapper
    /// dispatches without encoding errors.
    ///
    /// The handler may still reject for handler-internal reasons
    /// (RL1 on the path, scope attenuation against the caller's
    /// grants, etc.) — those are handler concerns, not wrapper
    /// concerns. We assert wire-shape correctness, not handler
    /// outcome.
    #[tokio::test(flavor = "current_thread")]
    async fn delegate_dispatches_with_local_peer_as_delegator() {
        let ctx = make_ctx();
        let me = ctx.identity_hash();
        ctx.role()
            .define("group/zeta", "viewer", sample_grants(), None)
            .await
            .expect("define");
        ctx.role()
            .assign("group/zeta", me, "viewer")
            .await
            .expect("assign");

        let result = ctx
            .role()
            .delegate("group/zeta", "viewer", me, me, sample_grants(), None)
            .await;
        match result {
            Ok(_) | Err(SdkError::HandlerError(_)) => {}
            Err(other) => panic!("unexpected wrapper-side error: {:?}", other),
        }
    }
}
