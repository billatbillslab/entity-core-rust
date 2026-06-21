//! Typed wrapper for `system/compute` extension operations.
//!
//! Phase 1 surface of the compute shell-verb sketch:
//! eval / install / uninstall / list / show. The first three are
//! direct dispatches to the `system/compute` handler; `list` and
//! `show` are SDK-side helpers built on top of the tree path where
//! the install handler writes subgraph metadata
//! (`/{peer_id}/system/compute/processes/{subgraph_id}`).
//!
//! ## Path-as-resource
//!
//! All three handler ops carry their target path in the EXECUTE
//! resource (PROPOSAL-PATH-AS-RESOURCE-HYGIENE §3.1 / P-COMPUTE-{1,2,3}):
//!
//! - `eval`: resource = expression path; the handler resolves it via
//!   the location index and evaluates the expression entity.
//! - `install`: resource = root expression path; params optionally
//!   carries `{result_path: <text>}` overriding the default
//!   `<root>/result` write target.
//! - `uninstall`: resource = subgraph path
//!   (`system/compute/processes/{id}`).
//!
//! Wrappers build the `ResourceTarget` via [`path_resource_opts`] and
//! pass an empty-or-minimal params entity.
//!
//! ## Eval result shape (per §F10)
//!
//! `system/compute:eval` returns at HTTP 200 in three forms:
//! 1. A `compute/result` entity with `{expression: bytes, value: any}`
//!    when the expression evaluates to a primitive.
//! 2. A `compute/error` entity directly when the expression produces
//!    an error value (F10: error values are *values*, not transport
//!    failures, so dispatch succeeds at 200).
//! 3. A `compute/closure` or arbitrary entity when the expression
//!    yields a non-primitive value.
//!
//! [`ComputeValue`] discriminates these via its `Error(Entity)` /
//! `Entity(Entity)` variants; callers can pattern-match or use
//! [`ComputeValue::is_error`] for the error path. Primitive variants
//! match the value shapes enumerated in `EXTENSION-COMPUTE §2.3`.
//!
//! ## Phase deferral
//!
//! - Phase 2 (Builder DSL) and Phase 3 (E7 lowering, reactive-cascade
//!   limits) are deferred per the consumer-pull guidance. The handler
//!   does not currently expose the Builder DSL via wire ops anyway —
//!   it would be a Rust-only authoring surface analogous to Go's
//!   `entitysdk/compute_builder.go`. Add when an authoring panel
//!   consumer materializes.
//!
//! ## Feature gating
//!
//! Available only when `entity-sdk` is built with the `compute`
//! feature enabled.

use crate::sdk::{PeerContext, SdkError};
use ciborium::Value;
use entity_capability::ResourceTarget;
use entity_entity::Entity;
use entity_handler::{ExecuteOptions, HandlerResult};
use entity_hash::Hash;

/// The `system/compute` extension handler URI. Exposed so transport-agnostic
/// consumers (e.g. a Worker-arm router that dispatches via a generic
/// `execute`) name the same handler the typed [`ComputeOps`] does.
pub const HANDLER: &str = "system/compute";

/// Operation names for the three dispatched compute ops.
pub const OP_EVAL: &str = "eval";
pub const OP_INSTALL: &str = "install";
pub const OP_UNINSTALL: &str = "uninstall";

/// Tree path under which the install handler writes subgraph metadata
/// (`system/compute/processes/{subgraph_id}`). Used by [`ComputeOps::list`]
/// + [`ComputeOps::show`] to walk installed subgraphs without needing a
/// dedicated `list`/`show` handler op. Public so a consumer building the
/// equivalent `list` as an L1 query (path-prefix scope) or a `show` get
/// names the same prefix.
pub const PROCESSES_PREFIX: &str = "system/compute/processes/";

/// Decoded compute value per `EXTENSION-COMPUTE §2.3`.
///
/// Primitive variants (`Null` … `Map`) carry the typed value directly;
/// `Hash` is a 33-byte content hash distinguished by length from a
/// generic bytes value. The `Entity` and `Closure` variants carry the
/// raw entity for non-primitive results (e.g. literal entities, value
/// types unrecognized by this decoder, or `compute/closure` values
/// the caller will instantiate). `Error` carries a `compute/error`
/// entity — per F10 the dispatch itself succeeded at 200 but the
/// computation produced an error *value*.
#[derive(Debug, Clone)]
pub enum ComputeValue {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Bytes(Vec<u8>),
    Text(String),
    /// Recognized via 33-byte length (1 tag + 32 digest) when decoding
    /// CBOR bytes-shaped values, since `system/hash` is a bare bstr
    /// extension per V7 §4.5. Callers who want raw bytes regardless
    /// use [`Self::as_raw_bytes`].
    Hash(Hash),
    Array(Vec<ComputeValue>),
    Map(Vec<(ComputeValue, ComputeValue)>),
    /// Non-primitive entity result. Caller dispatches on
    /// `entity.entity_type` to interpret.
    Entity(Entity),
    /// `compute/closure` result entity.
    Closure(Entity),
    /// `compute/error` value (F10). The handler returned status 200.
    Error(Entity),
}

impl ComputeValue {
    /// True when this is a `compute/error` value. The error variant
    /// carries the raw entity; use [`Self::as_entity`] to inspect it.
    pub fn is_error(&self) -> bool {
        matches!(self, ComputeValue::Error(_))
    }

    /// If the value is `Entity` / `Closure` / `Error`, return the
    /// underlying entity; otherwise `None`. Useful when the caller
    /// wants to round-trip the result through a typed decoder.
    pub fn as_entity(&self) -> Option<&Entity> {
        match self {
            ComputeValue::Entity(e) | ComputeValue::Closure(e) | ComputeValue::Error(e) => Some(e),
            _ => None,
        }
    }

    /// Treat the value as raw bytes regardless of whether the decoder
    /// promoted it to [`Self::Hash`]. Returns `None` for non-bytes
    /// variants.
    pub fn as_raw_bytes(&self) -> Option<&[u8]> {
        match self {
            ComputeValue::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }
}

/// Per-call dispatch options for `eval`. Empty by default. The
/// handler will fall back to peer / bounds / grant ceilings when
/// fields are `None`.
#[derive(Debug, Clone, Default)]
pub struct EvalOptions {
    /// Per-call max-ops cap. The effective budget is
    /// `min(this, bounds_budget, grant_constraint, default)` per
    /// `EXTENSION-COMPUTE §5.2`. Use sparingly — the handler ceiling
    /// is the safer default.
    pub budget: Option<u64>,
}

/// Decoded result of `system/compute:eval`. The `value` field is the
/// typed view; `result_entity` is the raw entity that came back from
/// the handler (helpful when the caller needs CBOR-fidelity access).
#[derive(Debug, Clone)]
pub struct ComputeEvalResult {
    /// Typed decode of the result.
    pub value: ComputeValue,
    /// Raw entity returned by the handler. Type is one of
    /// `compute/result`, `compute/error`, `compute/closure`, or the
    /// entity type of a non-primitive result.
    pub result_entity: Entity,
}

/// Decoded result of `system/compute:install` per the
/// `system/compute/install-result` entity shape.
#[derive(Debug, Clone)]
pub struct ComputeInstallResult {
    /// Tree path the subgraph metadata is bound at:
    /// `system/compute/processes/{deterministic_id}`.
    pub subgraph_path: String,
    /// Tree path where reactive evaluation writes the latest result
    /// (defaults to `<root>/result` when caller didn't supply
    /// `result_path` in install options).
    pub result_path: String,
    /// Walker-reported impure operations (handler dispatch targets,
    /// read paths, write paths). Exposed as the raw CBOR map; callers
    /// parse the fields they care about. See
    /// `extensions/compute/src/lib.rs:handle_install` for the
    /// production shape.
    pub impure_operations: Value,
}

/// Per-call install options. Empty for the common case (use default
/// `<root>/result`); supply `result_path` to redirect the reactive
/// write target.
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// Override the tree path where reactive evaluations are written
    /// (default: `<root_expression_path>/result`).
    pub result_path: Option<String>,
}

/// Decoded subgraph metadata entity (`system/compute/subgraph`).
/// Returned by [`ComputeOps::list`] and [`ComputeOps::show`].
#[derive(Debug, Clone)]
pub struct InstalledSubgraph {
    /// Tree path under `system/compute/processes/`.
    pub subgraph_path: String,
    /// Content hash of the subgraph metadata entity at
    /// [`Self::subgraph_path`].
    pub metadata_hash: Hash,
    /// Root expression path the subgraph was installed against.
    pub root_expression_path: String,
    /// Tree path the reactive engine writes the latest result to.
    pub result_path: String,
    /// Metadata status (typically `"active"` immediately after install).
    pub status: String,
    /// Content hash of the installation grant capability.
    pub installation_grant: Hash,
    /// Identity hash of the installer (EXECUTE `author`).
    pub installed_by: Hash,
}

/// Typed accessor for `system/compute` operations.
///
/// Created via [`PeerContext::compute`]. Borrows from the
/// `PeerContext`; futures returned by methods are `'static`.
pub struct ComputeOps<'a> {
    ctx: &'a PeerContext,
}

impl<'a> ComputeOps<'a> {
    pub(crate) fn new(ctx: &'a PeerContext) -> Self {
        Self { ctx }
    }

    /// One-shot evaluation of the expression at `expression_path`. Per
    /// `EXTENSION-COMPUTE §3.1`. Path-as-resource: `expression_path`
    /// goes in the EXECUTE resource, not params.
    ///
    /// Returns a [`ComputeEvalResult`] whose `value` is the typed
    /// decode. Per F10, an error *value* surfaces as
    /// `value = ComputeValue::Error(entity)` at status 200 — only
    /// dispatch / auth / 404-not-found failures map to
    /// [`SdkError::HandlerError`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn eval(
        &self,
        expression_path: impl Into<String>,
        options: EvalOptions,
    ) -> impl std::future::Future<Output = Result<ComputeEvalResult, SdkError>> + Send + 'static
    {
        let (params, opts) = eval_request(expression_path, options);
        let fut = self.ctx.execute(HANDLER, OP_EVAL, params, opts);
        async move { finish_eval(fut.await?) }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn eval(
        &self,
        expression_path: impl Into<String>,
        options: EvalOptions,
    ) -> impl std::future::Future<Output = Result<ComputeEvalResult, SdkError>> + 'static {
        let (params, opts) = eval_request(expression_path, options);
        let fut = self.ctx.execute(HANDLER, OP_EVAL, params, opts);
        async move { finish_eval(fut.await?) }
    }

    /// Install a reactive subgraph rooted at `root_expression_path`.
    /// Per `EXTENSION-COMPUTE §3.3`. Path-as-resource: the root path
    /// goes in the EXECUTE resource; only `result_path` (optional)
    /// rides in params.
    ///
    /// **Requires a caller capability** — the installation grant
    /// authorizes all subsequent reactive re-evaluations. Dispatched
    /// without one returns 403 `permission_denied` from the handler.
    ///
    /// Returns the [`ComputeInstallResult`] echoing the subgraph path
    /// + result path the handler chose.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn install(
        &self,
        root_expression_path: impl Into<String>,
        options: InstallOptions,
    ) -> impl std::future::Future<Output = Result<ComputeInstallResult, SdkError>> + Send + 'static
    {
        let (params, opts) = install_request(root_expression_path, options);
        let fut = self.ctx.execute(HANDLER, OP_INSTALL, params, opts);
        async move { finish_install(fut.await?) }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn install(
        &self,
        root_expression_path: impl Into<String>,
        options: InstallOptions,
    ) -> impl std::future::Future<Output = Result<ComputeInstallResult, SdkError>> + 'static {
        let (params, opts) = install_request(root_expression_path, options);
        let fut = self.ctx.execute(HANDLER, OP_INSTALL, params, opts);
        async move { finish_install(fut.await?) }
    }

    /// Uninstall the subgraph at `subgraph_path`. Per
    /// `EXTENSION-COMPUTE §3.4`. Path-as-resource — the path goes in
    /// the EXECUTE resource; params is the empty-shape carrier.
    ///
    /// Returns `Ok(())` on success. Handler returns
    /// `system/protocol/status {status: 200}` on success and 404
    /// `not_found` when the subgraph isn't installed at the supplied
    /// path.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn uninstall(
        &self,
        subgraph_path: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + Send + 'static {
        let (params, opts) = uninstall_request(subgraph_path);
        let fut = self.ctx.execute(HANDLER, OP_UNINSTALL, params, opts);
        async move { finish_uninstall(fut.await?) }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn uninstall(
        &self,
        subgraph_path: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + 'static {
        let (params, opts) = uninstall_request(subgraph_path);
        let fut = self.ctx.execute(HANDLER, OP_UNINSTALL, params, opts);
        async move { finish_uninstall(fut.await?) }
    }

    /// List installed subgraphs on the local peer. SDK-side helper —
    /// the Rust handler does not currently expose a `list` op; this
    /// reads from the tree path the install handler binds metadata at
    /// (`/{peer_id}/system/compute/processes/`).
    ///
    /// Sync L0 access — no dispatch, no capability check. Caller is
    /// expected to be the peer owner.
    pub fn list(&self) -> Vec<InstalledSubgraph> {
        let store = self.ctx.store();
        let prefix = format!("/{}/{}", self.ctx.peer_id(), PROCESSES_PREFIX);
        store
            .list_entities(&prefix)
            .into_iter()
            .filter_map(|(path, entity)| decode_subgraph_entity(&path, &entity))
            .collect()
    }

    /// Read the subgraph metadata at `subgraph_path`. Returns `None`
    /// when no entity is bound there or when the bound entity is not
    /// a `system/compute/subgraph`.
    ///
    /// Like [`Self::list`], this is an SDK-side helper that bypasses
    /// dispatch and reads the tree directly.
    pub fn show(&self, subgraph_path: &str) -> Option<InstalledSubgraph> {
        let qualified = if subgraph_path.starts_with('/') {
            subgraph_path.to_string()
        } else {
            format!("/{}/{}", self.ctx.peer_id(), subgraph_path)
        };
        let entity = self.ctx.store().get(&qualified)?;
        decode_subgraph_entity(&qualified, &entity)
    }
}

// ---------------------------------------------------------------------------
// Transport-agnostic marshalling.
//
// The typed `ComputeOps` above is the primary consumer (Direct-arm,
// PeerContext-bound). These free functions expose the same wire contract —
// request building + result decoding — so a consumer driving a *generic*
// `execute` over a different transport (e.g. a Worker-arm router that
// forwards EXECUTE over the worker wire and has no main-thread
// `PeerContext`) can dispatch compute ops without duplicating the param
// shapes or the three-form result decode. `ComputeOps` delegates to these:
// there is exactly one source of truth for the compute wire contract.
// ---------------------------------------------------------------------------

/// Build the `(params, opts)` for a `system/compute:eval` dispatch. The
/// expression path rides in the EXECUTE resource (path-as-resource); the
/// optional budget rides in params.
pub fn eval_request(
    expression_path: impl Into<String>,
    options: EvalOptions,
) -> (Entity, ExecuteOptions) {
    (
        build_eval_params(options.budget),
        path_resource_opts(expression_path.into()),
    )
}

/// Map a `system/compute:eval` [`HandlerResult`] to a typed
/// [`ComputeEvalResult`]. Dispatch / auth / 404 failures surface as
/// [`SdkError`]; per F10 an error *value* is a successful 200 carried in
/// `ComputeValue::Error`.
pub fn finish_eval(result: HandlerResult) -> Result<ComputeEvalResult, SdkError> {
    if let Some(err) = SdkError::from_handler_result(&result, "system/compute:eval") {
        return Err(err);
    }
    Ok(decode_eval_result(result.result))
}

/// Build the `(params, opts)` for a `system/compute:install` dispatch. The
/// root expression path rides in the EXECUTE resource; only the optional
/// `result_path` override rides in params.
pub fn install_request(
    root_expression_path: impl Into<String>,
    options: InstallOptions,
) -> (Entity, ExecuteOptions) {
    (
        build_install_params(options.result_path),
        path_resource_opts(root_expression_path.into()),
    )
}

/// Map a `system/compute:install` [`HandlerResult`] to a typed
/// [`ComputeInstallResult`].
pub fn finish_install(result: HandlerResult) -> Result<ComputeInstallResult, SdkError> {
    if let Some(err) = SdkError::from_handler_result(&result, "system/compute:install") {
        return Err(err);
    }
    decode_install_result(&result.result)
}

/// Build the `(params, opts)` for a `system/compute:uninstall` dispatch. The
/// subgraph path rides in the EXECUTE resource; params is the empty carrier.
pub fn uninstall_request(subgraph_path: impl Into<String>) -> (Entity, ExecuteOptions) {
    (empty_params(), path_resource_opts(subgraph_path.into()))
}

/// Map a `system/compute:uninstall` [`HandlerResult`] to `Ok(())` or a
/// dispatch error (e.g. 404 when the subgraph isn't installed at the path).
pub fn finish_uninstall(result: HandlerResult) -> Result<(), SdkError> {
    if let Some(err) = SdkError::from_handler_result(&result, "system/compute:uninstall") {
        return Err(err);
    }
    Ok(())
}

/// Build an `ExecuteOptions` carrying `path` as a single-target
/// resource (path-as-resource per PROPOSAL-PATH-AS-RESOURCE-HYGIENE).
fn path_resource_opts(path: String) -> ExecuteOptions {
    ExecuteOptions {
        resource: Some(ResourceTarget {
            targets: vec![path],
            exclude: vec![],
        }),
        ..Default::default()
    }
}

fn empty_params() -> Entity {
    let data = entity_ecf::to_ecf(&Value::Map(Vec::new()));
    Entity::new("primitive/any", data)
        .expect("empty primitive/any entity construction is infallible")
}

/// Build the eval-params body. The handler reads only `{budget: uint}`
/// from params data; absent budget falls through to handler defaults.
fn build_eval_params(budget: Option<u64>) -> Entity {
    let fields: Vec<(Value, Value)> = if let Some(b) = budget {
        vec![(
            entity_ecf::text("budget"),
            Value::Integer(ciborium::value::Integer::from(b)),
        )]
    } else {
        Vec::new()
    };
    let data = entity_ecf::to_ecf(&Value::Map(fields));
    Entity::new("primitive/any", data)
        .expect("eval-params entity construction is infallible")
}

/// Build the install-params body — only `result_path` (optional)
/// rides in params per P-COMPUTE-2.
fn build_install_params(result_path: Option<String>) -> Entity {
    let fields: Vec<(Value, Value)> = if let Some(p) = result_path {
        vec![(entity_ecf::text("result_path"), entity_ecf::text(&p))]
    } else {
        Vec::new()
    };
    let data = entity_ecf::to_ecf(&Value::Map(fields));
    Entity::new("primitive/any", data)
        .expect("install-params entity construction is infallible")
}

/// Decode whatever entity the eval handler returned into a typed
/// [`ComputeEvalResult`]. See module-level docs for the three result
/// shapes (compute/result, compute/error, other).
fn decode_eval_result(entity: Entity) -> ComputeEvalResult {
    let value = decode_compute_value_from_entity(&entity);
    ComputeEvalResult {
        value,
        result_entity: entity,
    }
}

/// Map an entity returned by `eval` to a typed `ComputeValue`.
///
/// - `compute/error` → `Error(entity)`.
/// - `compute/closure` → `Closure(entity)`.
/// - `compute/result` → decode the `value` field as a CBOR value and
///   convert to the typed primitive variant.
/// - Anything else → `Entity(entity)` (literal pass-through).
fn decode_compute_value_from_entity(entity: &Entity) -> ComputeValue {
    match entity.entity_type.as_str() {
        "compute/error" => ComputeValue::Error(entity.clone()),
        "compute/closure" => ComputeValue::Closure(entity.clone()),
        "compute/result" => {
            let val: Value = match ciborium::de::from_reader(entity.data.as_slice()) {
                Ok(v) => v,
                Err(_) => return ComputeValue::Entity(entity.clone()),
            };
            let map = match val.as_map() {
                Some(m) => m,
                None => return ComputeValue::Entity(entity.clone()),
            };
            for (k, v) in map {
                if k.as_text() == Some("value") {
                    return decode_compute_value_from_cbor(v);
                }
            }
            // compute/result with no value field — surface as raw entity.
            ComputeValue::Entity(entity.clone())
        }
        _ => ComputeValue::Entity(entity.clone()),
    }
}

/// Convert a CBOR value into the typed `ComputeValue` enum per §2.3.
fn decode_compute_value_from_cbor(v: &Value) -> ComputeValue {
    match v {
        Value::Null => ComputeValue::Null,
        Value::Bool(b) => ComputeValue::Bool(*b),
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            if n >= 0 && n > i64::MAX as i128 {
                ComputeValue::Uint(n as u64)
            } else {
                ComputeValue::Int(n as i64)
            }
        }
        Value::Float(f) => ComputeValue::Float(*f),
        Value::Bytes(b) => {
            // V7 §4.5: system/hash is a 33-byte bstr (1 tag + 32 digest).
            // Promote bytes of that exact length + a valid algorithm
            // tag to the typed Hash variant. Anything else stays as
            // raw bytes.
            if b.len() == 33 {
                if let Ok(h) = Hash::from_bytes(b) {
                    return ComputeValue::Hash(h);
                }
            }
            ComputeValue::Bytes(b.clone())
        }
        Value::Text(s) => ComputeValue::Text(s.clone()),
        Value::Array(arr) => {
            ComputeValue::Array(arr.iter().map(decode_compute_value_from_cbor).collect())
        }
        Value::Map(m) => ComputeValue::Map(
            m.iter()
                .map(|(k, val)| {
                    (
                        decode_compute_value_from_cbor(k),
                        decode_compute_value_from_cbor(val),
                    )
                })
                .collect(),
        ),
        // Tag/Other — surface as Null. The eval handler does not emit
        // tagged values in §2.3 so this branch is unreachable in
        // practice; if it does fire, the caller can pivot to
        // `result_entity` for raw access.
        _ => ComputeValue::Null,
    }
}

fn decode_install_result(entity: &Entity) -> Result<ComputeInstallResult, SdkError> {
    let val: Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode install result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("install result not a map".into()))?;

    let mut subgraph_path: Option<String> = None;
    let mut result_path: Option<String> = None;
    let mut impure: Value = Value::Null;

    for (k, v) in map {
        match k.as_text() {
            Some("subgraph_path") => subgraph_path = v.as_text().map(|s| s.to_string()),
            Some("result_path") => result_path = v.as_text().map(|s| s.to_string()),
            Some("impure_operations") => impure = v.clone(),
            _ => {}
        }
    }

    Ok(ComputeInstallResult {
        subgraph_path: subgraph_path
            .ok_or_else(|| SdkError::HandlerError("install result missing subgraph_path".into()))?,
        result_path: result_path
            .ok_or_else(|| SdkError::HandlerError("install result missing result_path".into()))?,
        impure_operations: impure,
    })
}

/// Decode a `system/compute/subgraph` metadata entity into the typed
/// [`InstalledSubgraph`]. Returns `None` if the entity isn't a
/// subgraph or is missing the required fields.
///
/// Public so a transport-agnostic `list`/`show` (an L1 query for
/// `system/compute/subgraph` under [`PROCESSES_PREFIX`], or a tree get)
/// decodes installed-subgraph metadata the same way [`ComputeOps::list`]
/// does — no app-side reimplementation of the field parse.
pub fn decode_subgraph_entity(path: &str, entity: &Entity) -> Option<InstalledSubgraph> {
    if entity.entity_type != "system/compute/subgraph" {
        return None;
    }
    let val: Value = ciborium::de::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;

    let mut root_expression_path: Option<String> = None;
    let mut result_path: Option<String> = None;
    let mut status: Option<String> = None;
    let mut installation_grant: Option<Hash> = None;
    let mut installed_by: Option<Hash> = None;

    for (k, v) in map {
        match k.as_text() {
            Some("root_expression_path") => {
                root_expression_path = v.as_text().map(|s| s.to_string())
            }
            Some("result_path") => result_path = v.as_text().map(|s| s.to_string()),
            Some("status") => status = v.as_text().map(|s| s.to_string()),
            Some("installation_grant") => {
                if let Value::Bytes(b) = v {
                    installation_grant = Hash::from_bytes(b).ok();
                }
            }
            Some("installed_by") => {
                if let Value::Bytes(b) = v {
                    installed_by = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    Some(InstalledSubgraph {
        subgraph_path: path.to_string(),
        metadata_hash: entity.content_hash,
        root_expression_path: root_expression_path?,
        result_path: result_path?,
        status: status?,
        installation_grant: installation_grant?,
        installed_by: installed_by?,
    })
}

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

    /// `eval` against a path with no entity returns 404 `not_found`.
    /// Probes dispatch + the path-as-resource shape on the error
    /// path before exercising real expression evaluation.
    #[tokio::test(flavor = "current_thread")]
    async fn eval_missing_path_returns_404() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/no/such/expr", pid);
        let r = ctx.compute().eval(path, EvalOptions::default()).await;
        match r {
            Err(SdkError::NotFound { status: 404, code, .. }) if code.as_deref() == Some("not_found") => {}
            other => panic!("expected 404 not_found, got {:?}", other),
        }
    }

    /// `eval` against a non-compute entity returns 400
    /// `invalid_expression`. Confirms the wrapper threads non-
    /// expression entities into the handler's §4.7 type check.
    #[tokio::test(flavor = "current_thread")]
    async fn eval_non_expression_returns_400() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/not-an-expr", pid);
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        ctx.store()
            .put(&path, Entity::new("app/note", data).unwrap())
            .unwrap();

        let r = ctx.compute().eval(path, EvalOptions::default()).await;
        match r {
            Err(SdkError::BadRequest { status: 400, code, .. })
                if code.as_deref() == Some("invalid_expression") => {}
            other => panic!("expected 400 invalid_expression, got {:?}", other),
        }
    }

    /// `eval` of a `compute/literal` returns the typed primitive
    /// value. Probes the full happy path: dispatch + result-entity
    /// shape + CBOR decode → typed `ComputeValue`.
    #[tokio::test(flavor = "current_thread")]
    async fn eval_literal_int_returns_typed_int() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/lit-int", pid);

        // compute/literal entity carrying an integer value.
        let lit_data = entity_ecf::to_ecf(&Value::Map(vec![(
            entity_ecf::text("value"),
            entity_ecf::integer(42),
        )]));
        ctx.store()
            .put(&path, Entity::new("compute/literal", lit_data).unwrap())
            .unwrap();

        let r = ctx
            .compute()
            .eval(path, EvalOptions::default())
            .await
            .expect("eval should succeed");
        assert_eq!(r.result_entity.entity_type, "compute/result");
        match r.value {
            ComputeValue::Int(42) => {}
            other => panic!("expected Int(42), got {:?}", other),
        }
    }

    /// `eval` of a `compute/literal` carrying text returns the typed
    /// text variant. Same path as the int test, different primitive
    /// shape — exercises the Text branch of the decoder.
    #[tokio::test(flavor = "current_thread")]
    async fn eval_literal_text_returns_typed_text() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/lit-text", pid);

        let lit_data = entity_ecf::to_ecf(&Value::Map(vec![(
            entity_ecf::text("value"),
            entity_ecf::text("hello"),
        )]));
        ctx.store()
            .put(&path, Entity::new("compute/literal", lit_data).unwrap())
            .unwrap();

        let r = ctx
            .compute()
            .eval(path, EvalOptions::default())
            .await
            .expect("eval should succeed");
        match r.value {
            ComputeValue::Text(s) if s == "hello" => {}
            other => panic!("expected Text(\"hello\"), got {:?}", other),
        }
    }

    /// `uninstall` against a path with no installed subgraph returns
    /// 404 `not_found`.
    #[tokio::test(flavor = "current_thread")]
    async fn uninstall_missing_returns_404() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/system/compute/processes/no-such-subgraph", pid);
        let r = ctx.compute().uninstall(path).await;
        match r {
            Err(SdkError::NotFound { status: 404, code, .. }) if code.as_deref() == Some("not_found") => {}
            other => panic!("expected 404 not_found, got {:?}", other),
        }
    }

    /// `list` on a fresh peer returns no subgraphs.
    #[test]
    fn list_fresh_peer_is_empty() {
        let ctx = make_ctx();
        let entries = ctx.compute().list();
        assert!(entries.is_empty(), "fresh peer → no subgraphs");
    }

    /// `show` on an unknown path returns None.
    #[test]
    fn show_missing_returns_none() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let r = ctx
            .compute()
            .show(&format!("/{}/system/compute/processes/no-such", pid));
        assert!(r.is_none());
    }

    /// `show` against an entity that's bound but not a subgraph type
    /// returns None — the decoder filters by entity_type.
    #[test]
    fn show_wrong_type_returns_none() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/system/compute/processes/foo", pid);
        let data = entity_ecf::to_ecf(&entity_ecf::text("decoy"));
        ctx.store()
            .put(&path, Entity::new("app/note", data).unwrap())
            .unwrap();
        let r = ctx.compute().show(&path);
        assert!(r.is_none(), "non-subgraph entity must not decode");
    }
}
