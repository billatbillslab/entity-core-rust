//! system/revision handler — versioning, merge, and sync operations.
//!
//! Provides 15 operations per EXTENSION-REVISION v2.1 for version DAG management,
//! branch/tag control, three-way merge with configurable strategies, and peer sync.

pub mod dag;
pub mod engine;
pub mod merge;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use entity_entity::Entity;
use entity_handler::{
    ExecuteOptions, Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_GATEWAY,
    STATUS_BAD_REQUEST, STATUS_CONFLICT, STATUS_INTERNAL_ERROR, STATUS_NOT_FOUND, STATUS_OK,
};
use entity_hash::Hash;
use entity_store::{CascadeResult, ContentStore, ExecutionContext, LocationIndex};
use entity_tree::trie;

use dag::{
    build_revision_entry, check_relationship, decode_revision_entry, detect_oscillation,
    find_common_ancestor, walk_history, Relationship, RevisionEntryData,
};
use merge::{merge_snapshots, store_conflict};

// ---------------------------------------------------------------------------
// Prefix hashing and path utilities (EXTENSION-REVISION v3.0 §3.1)
// ---------------------------------------------------------------------------

/// Resolve a bare prefix to absolute form (R2).
/// `project/` → `/{local_peer_id}/project/`; already-absolute paths pass through.
pub fn resolve_prefix(prefix: &str, local_peer_id: &str) -> String {
    if prefix.starts_with('/') {
        prefix.to_string()
    } else {
        format!("/{}/{}", local_peer_id, prefix)
    }
}

/// Compute the 66-character hex hash for a prefix subtree (R1).
/// Input MUST be an absolute prefix (call `resolve_prefix` first).
/// Hash = hex(content_hash(type="system/tree/path", data=ecf_encode(prefix))).
pub fn prefix_hash(absolute_prefix: &str) -> String {
    let ecf_data = entity_ecf::to_ecf(&entity_ecf::text(absolute_prefix));
    let hash = Hash::compute("system/tree/path", &ecf_data);
    hash.to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub(crate) fn rev_head_path(pid: &str, ph: &str) -> String {
    format!("/{}/system/revision/{}/head", pid, ph)
}
pub(crate) fn rev_active_branch_path(pid: &str, ph: &str) -> String {
    format!("/{}/system/revision/{}/active-branch", pid, ph)
}
pub(crate) fn rev_branch_path(pid: &str, ph: &str, name: &str) -> String {
    format!("/{}/system/revision/{}/branches/{}", pid, ph, name)
}
fn rev_branches_prefix(pid: &str, ph: &str) -> String {
    format!("/{}/system/revision/{}/branches/", pid, ph)
}
fn rev_tag_path(pid: &str, ph: &str, name: &str) -> String {
    format!("/{}/system/revision/{}/tags/{}", pid, ph, name)
}
fn rev_tags_prefix(pid: &str, ph: &str) -> String {
    format!("/{}/system/revision/{}/tags/", pid, ph)
}
fn rev_conflict_path(pid: &str, ph: &str, path: &str) -> String {
    format!("/{}/system/revision/{}/conflicts/{}", pid, ph, path)
}
fn rev_conflicts_prefix(pid: &str, ph: &str) -> String {
    format!("/{}/system/revision/{}/conflicts/", pid, ph)
}
/// Path to a remote-head binding: `/{pid}/system/revision/{ph}/remotes/{peer_id_hex}`.
/// V7 §1.4 v7.64: the `{peer_id_hex}` segment is lowercase hex of the
/// remote peer's `system/peer` entity content_hash — NOT Base58. Callers
/// receive a Base58 handle in `params.remote` and must pre-convert via
/// [`peer_remote_hex`].
fn rev_remote_path(pid: &str, ph: &str, peer_id_hex: &str) -> String {
    format!("/{}/system/revision/{}/remotes/{}", pid, ph, peer_id_hex)
}

/// Convert a Base58 PeerID (the `remote` field of push/pull params) to
/// its `{peer_id_hex}` form. Identity-form PIDs derive locally; SHA-256
/// form would need a cached `system/peer` entity (not threaded here).
/// Surfaces as `400 invalid_remote` when the conversion fails.
fn peer_remote_hex(remote_b58: &str) -> Result<String, HandlerError> {
    let pid = entity_crypto::PeerId::from(remote_b58);
    pid.identity_hex_local().ok_or_else(|| {
        HandlerError::InvalidParams(format!(
            "cannot derive {{peer_id_hex}} from PeerID {} (v7.64 §1.4: SHA-256-form PeerIDs need a cached `system/peer` entity; not supported here)",
            remote_b58
        ))
    })
}
fn rev_remotes_prefix(pid: &str, ph: &str) -> String {
    format!("/{}/system/revision/{}/remotes/", pid, ph)
}
pub(crate) fn rev_config_path(pid: &str, ph: &str) -> String {
    format!("/{}/system/revision/{}/config", pid, ph)
}

// ---------------------------------------------------------------------------
// Cascade warning collection (PROPOSAL R5/R6)
// ---------------------------------------------------------------------------

/// A cascade warning collected during a bulk tree operation (merge, checkout,
/// cherry-pick, revert).  207 Multi-Status writes (binding committed but a
/// cascade consumer halted) are collected as warnings rather than aborting.
#[derive(Debug, Clone)]
struct CascadeWarning {
    path: String,
    consumer_halted: String,
    error_code: u32,
}

/// Collect cascade warnings from a `CascadeResult`.
/// If `binding_committed` is false, returns `Err(path)` — the caller should
/// stop and report a partial result.  Otherwise appends warnings for any
/// halted consumers and returns `Ok(())`.
fn collect_cascade_warnings(
    cascade: &CascadeResult,
    path: &str,
    warnings: &mut Vec<CascadeWarning>,
) -> Result<(), String> {
    if !cascade.binding_committed {
        return Err(path.to_string());
    }
    for halt in &cascade.consumers_halted {
        warnings.push(CascadeWarning {
            path: path.to_string(),
            consumer_halted: halt.consumer_name.clone(),
            error_code: halt.error_code,
        });
    }
    Ok(())
}

/// Encode collected cascade warnings into an ECF array value suitable for
/// inclusion in a result entity.  Returns `None` when `warnings` is empty.
fn encode_cascade_warnings(warnings: &[CascadeWarning]) -> Option<entity_ecf::Value> {
    if warnings.is_empty() {
        return None;
    }
    let values: Vec<entity_ecf::Value> = warnings
        .iter()
        .map(|w| {
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("consumer_halted"),
                    entity_ecf::text(&w.consumer_halted),
                ),
                (
                    entity_ecf::text("error_code"),
                    entity_ecf::text(w.error_code.to_string()),
                ),
                (entity_ecf::text("path"), entity_ecf::text(&w.path)),
            ])
        })
        .collect();
    Some(entity_ecf::Value::Array(values))
}

/// The revision handler: system/revision with 16 operations.
pub struct RevisionHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    /// Per-prefix mutex for serializing commits.
    prefix_locks: Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    local_peer_id: String,
    qualified_pattern: String,
}

impl RevisionHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/revision", local_peer_id);
        Self {
            content_store,
            location_index,
            prefix_locks: Mutex::new(std::collections::HashMap::new()),
            local_peer_id,
            qualified_pattern,
        }
    }

    fn get_prefix_lock(&self, prefix: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.prefix_locks.lock().unwrap();
        locks
            .entry(prefix.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Qualify a bare prefix for tree data operations. Idempotent.
    fn qualify_tree_prefix(&self, prefix: &str) -> String {
        qualify_tree_prefix(prefix, &self.local_peer_id)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for RevisionHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        tracing::debug!(
            request_id = %ctx.request_id,
            operation = %ctx.operation,
            "revision: dispatching"
        );
        let result = match ctx.operation.as_str() {
            "commit" => self.handle_commit(ctx).await,
            "config" => self.handle_config(ctx).await,
            "merge-config" => self.handle_merge_config(ctx).await,
            "log" => self.handle_log(ctx).await,
            "status" => self.handle_status(ctx).await,
            "merge" => self.handle_merge(ctx).await,
            "resolve" => self.handle_resolve(ctx).await,
            "fetch" => self.handle_fetch(ctx).await,
            "pull" => self.handle_pull(ctx).await,
            "push" => self.handle_push(ctx).await,
            "find-ancestor" => self.handle_find_ancestor(ctx).await,
            "branch" => self.handle_branch(ctx).await,
            "checkout" => self.handle_checkout(ctx).await,
            "tag" => self.handle_tag(ctx).await,
            "diff" => self.handle_diff(ctx).await,
            "cherry-pick" => self.handle_cherry_pick(ctx).await,
            "revert" => self.handle_revert(ctx).await,
            "fetch-entities" => self.handle_fetch_entities(ctx).await,
            "fetch-diff" => self.handle_fetch_diff(ctx).await,
            _ => Ok(error_result(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown: {}", ctx.operation),
            )),
        };
        match &result {
            Ok(r) => tracing::debug!(
                request_id = %ctx.request_id,
                operation = %ctx.operation,
                status = r.status,
                "revision: completed"
            ),
            Err(e) => tracing::warn!(
                request_id = %ctx.request_id,
                operation = %ctx.operation,
                error = %e,
                "revision: error"
            ),
        }
        result
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "revision"
    }

    fn operations(&self) -> &[&str] {
        &[
            "branch",
            "checkout",
            "cherry-pick",
            "commit",
            "config",
            "diff",
            "fetch",
            "fetch-diff",
            "fetch-entities",
            "find-ancestor",
            "log",
            "merge",
            "merge-config",
            "pull",
            "push",
            "resolve",
            "revert",
            "status",
            "tag",
        ]
    }
}

// ---------------------------------------------------------------------------
// Commit (§4.3.1)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_commit(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let prefix = decode_commit_params(&ctx.params.data)?;

        let lock = self.get_prefix_lock(&prefix);
        let _guard = lock.lock().await;

        let (version_hash, root_hash, _parent): (Hash, Hash, Option<Hash>) =
            commit_logic::perform_commit(
                self.content_store.as_ref(),
                self.location_index.as_ref(),
                &prefix,
                &self.local_peer_id,
            )
            .map_err(HandlerError::Internal)?;

        // EXTENSION-REVISION §4.3.1 commit-result (authoritative handler wire
        // spec, line 699):
        //   {type: "system/revision/commit-result",
        //    data: {version: version_hash, root: trie_root_hash}}
        // Field NAMES are `version` and `root` (the VALUES are the version and
        // trie-root hashes). ECF length-then-lex key order: root (4) before
        // version (7). Go + the conformance oracle decode these names. The
        // prior G5 shape ({version_hash, trie_root, parent}) followed the
        // SDK-domain SDK-EXTENSION-OPERATIONS §4 descriptive naming, which
        // contradicts this protocol-domain spec — see docs/SPEC-AMBIGUITIES.md.
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("root"),
                entity_ecf::Value::Bytes(root_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(version_hash.to_bytes().to_vec()),
            ),
        ]));
        let result = Entity::new("system/revision/commit-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Config (PROPOSAL-REVISION-CONFIG-OPERATION §3.1, EXTENSION-REVISION §4.4.17)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_config(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let params = decode_config_params(&ctx.params.data)?;

        match params.action.as_str() {
            "set" => self.handle_config_set(ctx, &params).await,
            "delete" => self.handle_config_delete(ctx, &params).await,
            _ => Ok(error_result(STATUS_BAD_REQUEST, "config/invalid-action",
                &format!("action must be \"set\" or \"delete\", got {:?}", params.action))),
        }
    }

    async fn handle_config_set(
        &self,
        ctx: &HandlerContext,
        params: &ConfigParams,
    ) -> Result<HandlerResult, HandlerError> {
        let config_data = params.config_data.as_ref()
            .ok_or_else(|| HandlerError::InvalidParams("config field required for action \"set\"".into()))?;

        let config = engine::decode_revision_config(config_data)
            .ok_or_else(|| HandlerError::InvalidParams("invalid revision config entity data".into()))?;

        if let Err(e) = engine::validate_revision_config(&config) {
            return Ok(error_result(e.status, &e.code, &e.message));
        }

        let canonical = engine::canonicalize_prefix(&config.prefix);
        let abs_prefix = resolve_prefix(&config.prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);
        let config_path = rev_config_path(&self.local_peer_id, &ph);

        // CAS guard
        if let Some(ref expected) = params.expected_hash {
            let current = self.location_index.get(&config_path);
            if current.as_ref() != Some(expected) {
                return Ok(error_result(STATUS_CONFLICT, "config/concurrent-modification",
                    &format!("expected {:?}, actual {:?}", expected, current)));
            }
        }

        let previous_hash = self.location_index.get(&config_path);
        let was_auto_version = previous_hash
            .and_then(|h| self.content_store.get(&h))
            .and_then(|e| engine::decode_revision_config(&e.data))
            .map(|c| c.auto_version)
            .unwrap_or(false);

        let config_entity = Entity::new("system/revision/config", config_data.clone())
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let config_hash = self.content_store.put(config_entity)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        let emit_ctx = build_handler_emit_ctx(ctx);
        let tracking_path = engine::tracking_config_path(&self.local_peer_id, &canonical);
        let mut tracking_action: Option<String> = None;

        // §6.1 ordering: enable tracking-config FIRST when enabling auto-version
        let enabling = config.auto_version && !was_auto_version;
        if enabling {
            let tc = engine::build_tracking_config_entity(&canonical, true)
                .ok_or_else(|| HandlerError::Internal("failed to build tracking-config".into()))?;
            let tc_hash = self.content_store.put(tc)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            let tc_cascade = self.location_index
                .set_with_context(&tracking_path, tc_hash, emit_ctx.clone());
            if !tc_cascade.binding_committed {
                return Ok(error_result(STATUS_INTERNAL_ERROR,
                    "config/tracking-config-write-failed", "tracking-config binding rejected"));
            }
            tracking_action = Some(if previous_hash.is_some() { "updated" } else { "created" }.into());
        }

        // Write the config
        let cfg_cascade = self.location_index
            .set_with_context(&config_path, config_hash, emit_ctx.clone());
        if !cfg_cascade.binding_committed {
            return Ok(error_result(STATUS_INTERNAL_ERROR,
                "config/config-write-failed", "config binding rejected"));
        }

        // §6.1 ordering: disable tracking-config AFTER config write
        if !config.auto_version && was_auto_version {
            let (_, _cascade) = self.location_index
                .remove_with_context(&tracking_path, emit_ctx);
            tracking_action = Some("deleted".into());
        }

        Ok(HandlerResult::ok(build_config_result(
            &config_path, Some(config_hash), previous_hash,
            tracking_action.as_ref().map(|_| tracking_path.as_str()),
            tracking_action.as_deref(),
        )?))
    }

    async fn handle_config_delete(
        &self,
        ctx: &HandlerContext,
        params: &ConfigParams,
    ) -> Result<HandlerResult, HandlerError> {
        // To find the config path, we need to resolve the prefix from the
        // config entity stored at the old path. Since config_delete needs
        // the prefix to compute ph, we use the name parameter to look up
        // the config first. Under the new scheme the caller must provide
        // the prefix in the config data or we derive from the stored entity.
        // For now, resolve via the name param treated as a prefix.
        let abs_prefix = resolve_prefix(&params.name, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);
        let config_path = rev_config_path(&self.local_peer_id, &ph);

        let previous_hash = self.location_index.get(&config_path);
        let previous_hash = match previous_hash {
            Some(h) => h,
            None => return Ok(error_result(STATUS_NOT_FOUND, "config/not-found",
                &format!("no config at name {:?}", params.name))),
        };

        if let Some(ref expected) = params.expected_hash {
            if *expected != previous_hash {
                return Ok(error_result(STATUS_CONFLICT, "config/concurrent-modification",
                    &format!("expected {:?}, actual {:?}", expected, previous_hash)));
            }
        }

        let prev_config = self.content_store.get(&previous_hash)
            .and_then(|e| engine::decode_revision_config(&e.data));
        let was_auto_version = prev_config.as_ref().map(|c| c.auto_version).unwrap_or(false);

        let emit_ctx = build_handler_emit_ctx(ctx);
        let mut tracking_action: Option<String> = None;
        let mut tracking_path_out: Option<String> = None;

        // Delete config binding
        let (_, _cascade) = self.location_index
            .remove_with_context(&config_path, emit_ctx.clone());

        // Delete tracking-config if was auto-versioned
        if was_auto_version {
            if let Some(ref prev) = prev_config {
                let canonical = engine::canonicalize_prefix(&prev.prefix);
                let tp = engine::tracking_config_path(&self.local_peer_id, &canonical);
                let (_, _cascade) = self.location_index.remove_with_context(&tp, emit_ctx);
                tracking_path_out = Some(tp);
                tracking_action = Some("deleted".into());
            }
        }

        Ok(HandlerResult::ok(build_config_result(
            &config_path, None, Some(previous_hash),
            tracking_path_out.as_deref(),
            tracking_action.as_deref(),
        )?))
    }
}

// ---------------------------------------------------------------------------
// Merge-config (EXTENSION-REVISION §2.3 / §5.1)
// ---------------------------------------------------------------------------
//
// Merge-config entities are stored at `system/revision/config/merge/path/{name}`
// (per-path) or `system/revision/config/merge/type/{type_name}` (per-type).
// Spec §2.3: writes MUST reject `deletion_resolution: lww` and
// `deletion_resolution: keep-both` with `invalid_strategy` at config-write
// time. The validation cannot happen on read (the spec explicitly demands
// rejection at write); direct tree.put bypasses validation. This operation
// is the rejection point.

impl RevisionHandler {
    async fn handle_merge_config(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let params = decode_merge_config_params(&ctx.params.data)?;

        // Validate scope.
        let scope_segment = match params.scope.as_str() {
            "path" => "path",
            "type" => "type",
            other => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_scope",
                    &format!("scope must be \"path\" or \"type\", got {:?}", other),
                ));
            }
        };

        let target_path = format!(
            "/{}/system/revision/config/merge/{}/{}",
            self.local_peer_id, scope_segment, params.name
        );

        // CAS guard runs for both set and delete — §4.4.18 algorithm.
        if let Some(ref expected) = params.expected_hash {
            let current = self.location_index.get(&target_path);
            if current.as_ref() != Some(expected) {
                return Ok(error_result(
                    STATUS_CONFLICT,
                    "stale_expected_hash",
                    &format!("expected {:?}, actual {:?}", expected, current),
                ));
            }
        }

        match params.action.as_str() {
            "set" => {
                let config_data = params.config_data.as_ref().ok_or_else(|| {
                    HandlerError::InvalidParams("missing_config".into())
                })?;

                // EXTENSION-REVISION v3.1 §2.3 strategy-rejection contract:
                // `deletion_resolution: lww` / `keep-both` MUST be rejected
                // with 400 `invalid_strategy` at config-write time.
                if let Some(rejected) = validate_merge_config_for_write(config_data) {
                    return Ok(error_result(
                        STATUS_BAD_REQUEST,
                        "invalid_strategy",
                        &format!(
                            "deletion_resolution: {:?} is not a valid value (see EXTENSION-REVISION §2.3); \
                             use one of preserve-on-conflict | deletion-wins | three-way-fallthrough \
                             | deterministic | <handler-path>",
                            rejected
                        ),
                    ));
                }

                let config_entity =
                    Entity::new("system/revision/merge-config", config_data.clone())
                        .map_err(|e| HandlerError::Internal(e.to_string()))?;
                let config_hash = config_entity.content_hash;

                // §4.4.18 idempotency: re-issuing identical content
                // returns status "no_change"; no tree write, no new
                // content-store entry.
                let current_hash = self.location_index.get(&target_path);
                if current_hash == Some(config_hash) {
                    return Ok(HandlerResult::ok(build_merge_config_result(
                        &target_path,
                        Some(config_hash),
                        "no_change",
                    )?));
                }

                self.content_store
                    .put(config_entity)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                self.location_index.set(&target_path, config_hash);
                Ok(HandlerResult::ok(build_merge_config_result(
                    &target_path,
                    Some(config_hash),
                    "set",
                )?))
            }
            "delete" => {
                let previous_hash = match self.location_index.get(&target_path) {
                    Some(h) => h,
                    None => {
                        return Ok(error_result(
                            STATUS_NOT_FOUND,
                            "config/not-found",
                            &format!("no merge-config at {}", target_path),
                        ));
                    }
                };
                let _ = previous_hash;
                self.location_index.remove(&target_path);
                Ok(HandlerResult::ok(build_merge_config_result(
                    &target_path,
                    None,
                    "deleted",
                )?))
            }
            other => Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_action",
                &format!("action must be \"set\" or \"delete\", got {:?}", other),
            )),
        }
    }
}

/// Build a `system/revision/merge-config-result` entity per §4.4.18:
/// fields `path`, `hash` (optional, absent on delete), `status`
/// ("set" | "deleted" | "no_change").
fn build_merge_config_result(
    path: &str,
    hash: Option<Hash>,
    status: &str,
) -> Result<Entity, HandlerError> {
    let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = vec![
        (entity_ecf::text("path"), entity_ecf::text(path)),
        (entity_ecf::text("status"), entity_ecf::text(status)),
    ];
    if let Some(h) = hash {
        fields.push((
            entity_ecf::text("hash"),
            entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    // ECF deterministic key ordering.
    fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    Entity::new("system/revision/merge-config-result", data)
        .map_err(|e| HandlerError::Internal(e.to_string()))
}

struct MergeConfigParams {
    scope: String,
    name: String,
    action: String,
    config_data: Option<Vec<u8>>,
    expected_hash: Option<Hash>,
}

fn decode_merge_config_params(data: &[u8]) -> Result<MergeConfigParams, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data).map_err(|e| {
        HandlerError::InvalidParams(format!("merge-config/invalid-params: {}", e))
    })?;
    let map = val.as_map().ok_or_else(|| {
        HandlerError::InvalidParams("merge-config/invalid-params: expected map".into())
    })?;

    let mut scope = None;
    let mut name = None;
    let mut action = None;
    let mut config_data = None;
    let mut expected_hash = None;

    for (k, v) in map {
        match k.as_text() {
            Some("scope") => scope = v.as_text().map(|s| s.to_string()),
            Some("name") => name = v.as_text().map(|s| s.to_string()),
            Some("action") => action = v.as_text().map(|s| s.to_string()),
            Some("config") => {
                if !v.is_null() {
                    let mut buf = Vec::new();
                    ciborium::into_writer(v, &mut buf).map_err(|e| {
                        HandlerError::InvalidParams(format!("config encode: {}", e))
                    })?;
                    config_data = Some(buf);
                }
            }
            Some("expected_hash") => {
                if let Some(b) = v.as_bytes() {
                    expected_hash = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }
    Ok(MergeConfigParams {
        scope: scope.ok_or_else(|| {
            HandlerError::InvalidParams("merge-config/missing-scope".into())
        })?,
        name: name
            .ok_or_else(|| HandlerError::InvalidParams("merge-config/missing-name".into()))?,
        action: action.ok_or_else(|| {
            HandlerError::InvalidParams("merge-config/missing-action".into())
        })?,
        config_data,
        expected_hash,
    })
}

/// Validate a `system/revision/merge-config` entity's `data` for write.
/// Returns `Some(rejected_value)` if `deletion_resolution` carries a
/// MUST-reject value (`lww` or `keep-both`); `None` otherwise.
/// EXTENSION-REVISION v3.1 §2.3 lines 217–219.
fn validate_merge_config_for_write(data: &[u8]) -> Option<String> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("deletion_resolution") {
            if let Some(s) = v.as_text() {
                if merge::DeletionResolution::is_rejected_at_config_write(s) {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

struct ConfigParams {
    name: String,
    action: String,
    config_data: Option<Vec<u8>>,
    expected_hash: Option<Hash>,
}

fn decode_config_params(data: &[u8]) -> Result<ConfigParams, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("config/invalid-params: {}", e)))?;
    let map = val.as_map()
        .ok_or_else(|| HandlerError::InvalidParams("config/invalid-params: expected map".into()))?;

    let mut name = None;
    let mut action = None;
    let mut config_data = None;
    let mut expected_hash = None;

    for (k, v) in map {
        match k.as_text() {
            Some("name") => name = v.as_text().map(|s| s.to_string()),
            Some("action") => action = v.as_text().map(|s| s.to_string()),
            Some("config") => {
                if !v.is_null() {
                    let mut buf = Vec::new();
                    ciborium::into_writer(v, &mut buf)
                        .map_err(|e| HandlerError::InvalidParams(format!("config encode: {}", e)))?;
                    config_data = Some(buf);
                }
            }
            Some("expected_hash") => {
                if !v.is_null() {
                    if let Some(bytes) = v.as_bytes() {
                        expected_hash = Some(Hash::from_bytes(bytes)
                            .map_err(|e| HandlerError::InvalidParams(format!("expected_hash: {}", e)))?);
                    }
                }
            }
            _ => {}
        }
    }

    let name = name.ok_or_else(|| HandlerError::InvalidParams("config/missing-name".into()))?;
    if name.is_empty() {
        return Err(HandlerError::InvalidParams("config/missing-name: name must not be empty".into()));
    }
    let action = action.ok_or_else(|| HandlerError::InvalidParams("config/invalid-action: missing".into()))?;

    Ok(ConfigParams { name, action, config_data, expected_hash })
}

fn build_handler_emit_ctx(ctx: &HandlerContext) -> ExecutionContext {
    let bare_pattern = entity_entity::EntityUri::strip_peer_prefix(&ctx.pattern);
    ExecutionContext {
        chain_id: ctx.bounds.as_ref().and_then(|b| b.chain_id.clone()),
        parent_chain_id: ctx.bounds.as_ref().and_then(|b| b.parent_chain_id.clone()),
        author: ctx.author,
        caller_capability: ctx.capability_hash,
        request_id: Some(ctx.request_id.clone()),
        capability: ctx.capability_hash,
        handler_grant: ctx.handler_grant_hash,
        handler_pattern: Some(bare_pattern.to_string()),
        operation: Some(ctx.operation.clone()),
        cascade_depth: 0,
        clock: None,
    }
}

fn build_config_result(
    config_path: &str,
    config_hash: Option<Hash>,
    previous_hash: Option<Hash>,
    tracking_path: Option<&str>,
    tracking_action: Option<&str>,
) -> Result<Entity, HandlerError> {
    use entity_ecf::{text, Value};
    let mut fields = vec![
        (text("config_path"), text(config_path)),
    ];
    if let Some(h) = config_hash {
        fields.push((text("config_hash"), Value::Bytes(h.to_bytes().to_vec())));
    }
    if let Some(h) = previous_hash {
        fields.push((text("previous_hash"), Value::Bytes(h.to_bytes().to_vec())));
    }
    if let Some(tp) = tracking_path {
        fields.push((text("tracking_config_path"), text(tp)));
    }
    if let Some(ta) = tracking_action {
        fields.push((text("tracking_config_action"), text(ta)));
    }
    let data = entity_ecf::to_ecf(&Value::Map(fields));
    Entity::new("system/revision/config-result", data)
        .map_err(|e| HandlerError::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// Log (§4.3.2)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_log(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (prefix, limit, since) = decode_log_params(&ctx.params.data)?;
        let effective_limit = limit.unwrap_or(50);

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);
        let head_path = rev_head_path(&self.local_peer_id, &ph);
        let head_hash = match self.location_index.get(&head_path) {
            Some(h) => h,
            None => {
                // No versions yet
                let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("has_more"),
                        entity_ecf::bool_val(false),
                    ),
                    (
                        entity_ecf::text("prefix"),
                        entity_ecf::text(&prefix),
                    ),
                    (
                        entity_ecf::text("versions"),
                        entity_ecf::Value::Array(vec![]),
                    ),
                ]));
                let result = Entity::new("system/revision/log-result", data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                let envelope = build_envelope_result(result, std::collections::HashMap::new());
                return Ok(HandlerResult::ok(envelope));
            }
        };

        // W2: pass since to walk_history; fetch limit+1 to detect has_more
        let history = walk_history(
            self.content_store.as_ref(),
            head_hash,
            effective_limit + 1,
            since,
        );

        let has_more = history.len() > effective_limit;

        // Collect version hashes and include version entities in response
        let mut included = std::collections::HashMap::new();
        let mut version_hash_values = Vec::new();
        for h in history.iter().take(effective_limit) {
            version_hash_values.push(entity_ecf::Value::Bytes(h.to_bytes().to_vec()));
            if let Some(entity) = self.content_store.get(h) {
                included.insert(*h, entity);
            }
        }

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("has_more"),
                entity_ecf::bool_val(has_more),
            ),
            (
                entity_ecf::text("prefix"),
                entity_ecf::text(&prefix),
            ),
            (
                entity_ecf::text("versions"),
                entity_ecf::Value::Array(version_hash_values),
            ),
        ]));
        let result = Entity::new("system/revision/log-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let envelope = build_envelope_result(result, included);
        Ok(HandlerResult::ok(envelope))
    }
}

// ---------------------------------------------------------------------------
// Status (§4.3.3)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_status(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let prefix = decode_prefix_only(&ctx.params.data)?;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);
        let head_path = rev_head_path(&self.local_peer_id, &ph);
        let head_hash = self.location_index.get(&head_path);

        // Count conflicts
        let conflict_prefix = rev_conflicts_prefix(&self.local_peer_id, &ph);
        let conflict_count = self.location_index.list(&conflict_prefix).len();

        // Read remote heads
        let remotes_prefix = rev_remotes_prefix(&self.local_peer_id, &ph);
        let remote_entries = self.location_index.list(&remotes_prefix);
        let mut remote_pairs = Vec::new();
        for entry in &remote_entries {
            // Path format: /{pid}/system/revision/{ph}/remotes/{peer_id}
            let rest = entry.path.strip_prefix(&remotes_prefix).unwrap_or("");
            if !rest.is_empty() {
                remote_pairs.push((
                    entity_ecf::text(rest),
                    entity_ecf::Value::Bytes(entry.hash.to_bytes().to_vec()),
                ));
            }
        }

        let mut fields = vec![
            (
                entity_ecf::text("conflicts"),
                entity_ecf::integer(conflict_count as i64),
            ),
        ];

        if let Some(h) = head_hash {
            fields.push((
                entity_ecf::text("head"),
                entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
            ));
        }

        // W1: pending = number of path changes since last version
        let pending_count = match head_hash {
            Some(h) => {
                let current = self.compute_snapshot_bindings(&prefix);
                match self.get_version_bindings(h) {
                    Ok(head_bindings) => {
                        let mut diff = 0usize;
                        for (p, hash) in &current {
                            if head_bindings.get(p) != Some(hash) {
                                diff += 1;
                            }
                        }
                        for p in head_bindings.keys() {
                            if !current.contains_key(p) {
                                diff += 1;
                            }
                        }
                        diff
                    }
                    Err(_) => 0,
                }
            }
            None => self.compute_snapshot_bindings(&prefix).len(),
        };
        fields.push((
            entity_ecf::text("pending"),
            entity_ecf::integer(pending_count as i64),
        ));

        fields.push((
            entity_ecf::text("prefix"),
            entity_ecf::text(&prefix),
        ));

        if !remote_pairs.is_empty() {
            fields.push((
                entity_ecf::text("remotes"),
                entity_ecf::Value::Map(remote_pairs),
            ));
        }

        // Sort by key for ECF
        fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let result = Entity::new("system/revision/status", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Find ancestor (§4.3.9)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_find_ancestor(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (version_a, version_b) = decode_ancestor_params(&ctx.params.data)?;

        let ancestor = find_common_ancestor(self.content_store.as_ref(), version_a, version_b);

        let mut fields = Vec::new();
        if let Some(a) = ancestor {
            fields.push((
                entity_ecf::text("ancestor"),
                entity_ecf::Value::Bytes(a.to_bytes().to_vec()),
            ));
        }

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let result = Entity::new("system/revision/ancestor-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Branch (§4.3.10)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_branch(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (prefix, action, name, from) = decode_branch_params(&ctx.params.data)?;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        match action.as_str() {
            "create" => {
                let branch_name = name.ok_or_else(|| {
                    HandlerError::InvalidParams("name required for create".into())
                })?;

                // Default to current head
                let version_hash = if let Some(from_hash) = from {
                    from_hash
                } else {
                    let head_path = rev_head_path(&self.local_peer_id, &ph);
                    self.location_index.get(&head_path).ok_or_else(|| {
                        HandlerError::InvalidParams("no head: cannot create branch".into())
                    })?
                };

                let branch_path = rev_branch_path(&self.local_peer_id, &ph, &branch_name);

                // Reject duplicate branch names
                if self.location_index.get(&branch_path).is_some() {
                    return Ok(error_result(
                        STATUS_CONFLICT,
                        "branch_exists",
                        &format!("branch '{}' already exists", branch_name),
                    ));
                }

                self.location_index.set(&branch_path, version_hash);

                let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                    "branch" => entity_ecf::text(&branch_name),
                    "status" => entity_ecf::text("created"),
                    "version" => entity_ecf::Value::Bytes(version_hash.to_bytes().to_vec())
                });
                let result = Entity::new("system/revision/branch-result", data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                Ok(HandlerResult {
                    status: STATUS_OK,
                    result,
                included: std::collections::HashMap::new(),
                })
            }
            "list" => {
                let branch_pfx = rev_branches_prefix(&self.local_peer_id, &ph);
                let entries = self.location_index.list(&branch_pfx);

                let branches: Vec<_> = entries
                    .iter()
                    .map(|e| {
                        let name = e.path.strip_prefix(&branch_pfx).unwrap_or(&e.path);
                        (
                            entity_ecf::text(name),
                            entity_ecf::Value::Bytes(e.hash.to_bytes().to_vec()),
                        )
                    })
                    .collect();

                let active_name = self.read_active_branch(&ph);

                let mut fields = vec![];
                if let Some(ref name) = active_name {
                    fields.push((entity_ecf::text("active"), entity_ecf::text(name)));
                }
                fields.push((
                    entity_ecf::text("branches"),
                    entity_ecf::Value::Map(branches),
                ));

                fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));

                let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
                let result = Entity::new("system/revision/branch-result", data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                Ok(HandlerResult {
                    status: STATUS_OK,
                    result,
                included: std::collections::HashMap::new(),
                })
            }
            "delete" => {
                let branch_name = name.ok_or_else(|| {
                    HandlerError::InvalidParams("name required for delete".into())
                })?;

                // Cannot delete active branch
                let active = self.read_active_branch(&ph);
                if active.as_deref() == Some(branch_name.as_str()) {
                    return Ok(error_result(
                        STATUS_BAD_REQUEST,
                        "active_branch",
                        "cannot delete the active branch",
                    ));
                }

                let branch_path = rev_branch_path(&self.local_peer_id, &ph, &branch_name);
                if self.location_index.get(&branch_path).is_none() {
                    return Ok(error_result(
                        STATUS_NOT_FOUND,
                        "branch_not_found",
                        &format!("branch '{}' not found", branch_name),
                    ));
                }

                self.location_index.remove(&branch_path);

                let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                    "branch" => entity_ecf::text(&branch_name),
                    "status" => entity_ecf::text("deleted")
                });
                let result = Entity::new("system/revision/branch-result", data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                Ok(HandlerResult {
                    status: STATUS_OK,
                    result,
                included: std::collections::HashMap::new(),
                })
            }
            _ => Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_action",
                &format!("unknown branch action: {}", action),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Tag (§4.3.12)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_tag(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (prefix, action, name, version) = decode_tag_params(&ctx.params.data)?;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        match action.as_str() {
            "create" => {
                let tag_name = name.ok_or_else(|| {
                    HandlerError::InvalidParams("name required for create".into())
                })?;

                let version_hash = if let Some(vh) = version {
                    vh
                } else {
                    let head_path = rev_head_path(&self.local_peer_id, &ph);
                    self.location_index.get(&head_path).ok_or_else(|| {
                        HandlerError::InvalidParams("no head: nothing to tag".into())
                    })?
                };

                let tag_path = rev_tag_path(&self.local_peer_id, &ph, &tag_name);
                if self.location_index.get(&tag_path).is_some() {
                    return Ok(error_result(
                        STATUS_CONFLICT,
                        "tag_exists",
                        &format!("tag '{}' already exists (tags are immutable)", tag_name),
                    ));
                }

                self.location_index.set(&tag_path, version_hash);

                let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                    "status" => entity_ecf::text("created"),
                    "tag" => entity_ecf::text(&tag_name),
                    "version" => entity_ecf::Value::Bytes(version_hash.to_bytes().to_vec())
                });
                let result = Entity::new("system/revision/tag-result", data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                Ok(HandlerResult {
                    status: STATUS_OK,
                    result,
                included: std::collections::HashMap::new(),
                })
            }
            "list" => {
                let tag_pfx = rev_tags_prefix(&self.local_peer_id, &ph);
                let entries = self.location_index.list(&tag_pfx);

                let tags: Vec<_> = entries
                    .iter()
                    .map(|e| {
                        let name = e.path.strip_prefix(&tag_pfx).unwrap_or(&e.path);
                        (
                            entity_ecf::text(name),
                            entity_ecf::Value::Bytes(e.hash.to_bytes().to_vec()),
                        )
                    })
                    .collect();

                let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                    entity_ecf::text("tags"),
                    entity_ecf::Value::Map(tags),
                )]));
                let result = Entity::new("system/revision/tag-result", data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                Ok(HandlerResult {
                    status: STATUS_OK,
                    result,
                included: std::collections::HashMap::new(),
                })
            }
            "delete" => {
                let tag_name = name.ok_or_else(|| {
                    HandlerError::InvalidParams("name required for delete".into())
                })?;

                let tag_path = rev_tag_path(&self.local_peer_id, &ph, &tag_name);
                if self.location_index.get(&tag_path).is_none() {
                    return Ok(error_result(
                        STATUS_NOT_FOUND,
                        "tag_not_found",
                        &format!("tag '{}' not found", tag_name),
                    ));
                }

                self.location_index.remove(&tag_path);

                let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                    "status" => entity_ecf::text("deleted"),
                    "tag" => entity_ecf::text(&tag_name)
                });
                let result = Entity::new("system/revision/tag-result", data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                Ok(HandlerResult {
                    status: STATUS_OK,
                    result,
                included: std::collections::HashMap::new(),
                })
            }
            _ => Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_action",
                &format!("unknown tag action: {}", action),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Checkout (§4.3.11)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_checkout(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (prefix, branch, version_hash) = decode_checkout_params(&ctx.params.data)?;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        let lock = self.get_prefix_lock(&prefix);
        let _guard = lock.lock().await;

        // Resolve target version
        let (target_version, target_branch) = if let Some(ref branch_name) = branch {
            let branch_path = rev_branch_path(&self.local_peer_id, &ph, branch_name);
            let vh = self.location_index.get(&branch_path).ok_or_else(|| {
                HandlerError::InvalidParams(format!("branch '{}' not found", branch_name))
            })?;
            (vh, Some(branch_name.clone()))
        } else if let Some(vh) = version_hash {
            (vh, None) // detached HEAD
        } else {
            return Err(HandlerError::InvalidParams(
                "must specify branch or version".into(),
            ));
        };

        // checkout_under_auto_version policy (PROPOSAL-REVISION-AUTO-VERSION-FIX
        // §6A.4). If auto-version is ON for this prefix, checkout is a state-
        // restoration operation that generates intermediate versions. The policy
        // field lets operators choose allow/warn/deny.
        let (auto_version_on, policy) = self.auto_version_policy_for(&prefix);
        if auto_version_on && policy == "deny" {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "checkout_denied_under_auto_version",
                "checkout is denied while auto_version is enabled for this prefix \
                 (checkout_under_auto_version=\"deny\"); use revision/diff, \
                 revision/log, or revision/fetch for read-only inspection",
            ));
        }

        // Get target bindings via trie
        let target_snap_bindings = self.get_version_bindings(target_version)?;

        // S1: check for uncommitted changes (advisory warning per §4.4.12)
        let head_path = rev_head_path(&self.local_peer_id, &ph);
        let live_tree_bindings = self.compute_snapshot_bindings(&prefix);
        // EXTENSION-REVISION v3.2 §4.4.12 (A.3) version-transcription
        // invariant: checkout's diff baseline MUST be the committed local
        // head trie, NOT the live tree. Live-tree paths not in either
        // version (in-flight writes pending AV capture, untracked paths,
        // prior app state) MUST be preserved. Empty-trie fallback when
        // there is no committed head yet (first-ever sync).
        let committed_head_bindings = self
            .location_index
            .get(&head_path)
            .and_then(|h| self.get_version_bindings(h).ok())
            .unwrap_or_default();
        let has_uncommitted = committed_head_bindings != live_tree_bindings;

        // Advance head and active-branch BEFORE applying bindings (§6A rule).
        // Under auto-version ON, intermediate writes created while applying
        // the target snapshot descend from target_version rather than orphaning.
        self.location_index.set(&head_path, target_version);
        if let Some(ref name) = target_branch {
            self.set_active_branch(&ph, name);
        } else {
            // Detached HEAD — clear active branch.
            let ab_path = rev_active_branch_path(&self.local_peer_id, &ph);
            self.location_index.remove(&ab_path);
        }

        // Apply target snapshot to tree using committed-head trie as
        // baseline (§4.4.12 v3.2). Removable set is exactly paths in
        // committed-head-trie ∧ absent-from-target — live-tree-only
        // paths are preserved.
        let cascade_warnings = self.apply_snapshot_diff(&prefix, &committed_head_bindings, &target_snap_bindings)
            .map_err(|rejected| HandlerError::Internal(
                format!("checkout binding rejected at {}", rejected),
            ))?;

        // Post-op head. Under auto-version OFF it equals target_version; under
        // auto-version ON it is the final intermediate V_N whose root matches
        // target_version.root (§6A.4 "Result structure").
        let final_head = self
            .location_index
            .get(&head_path)
            .unwrap_or(target_version);

        let mut fields = vec![
            (
                entity_ecf::text("head"),
                entity_ecf::Value::Bytes(final_head.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("status"),
                entity_ecf::text("checked_out"),
            ),
            (
                entity_ecf::text("target_version"),
                entity_ecf::Value::Bytes(target_version.to_bytes().to_vec()),
            ),
            // Kept for backward compatibility with callers that look at `version`.
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(target_version.to_bytes().to_vec()),
            ),
        ];
        if auto_version_on && policy == "warn" && final_head != target_version {
            fields.push((
                entity_ecf::text("note"),
                entity_ecf::text(
                    "auto_version produced intermediate versions; head differs from target_version",
                ),
            ));
        }
        if let Some(ref name) = target_branch {
            fields.push((entity_ecf::text("branch"), entity_ecf::text(name)));
        }
        if let Some(warnings_val) = encode_cascade_warnings(&cascade_warnings) {
            fields.push((entity_ecf::text("cascade_warnings"), warnings_val));
        }
        if has_uncommitted {
            fields.push((
                entity_ecf::text("uncommitted_changes"),
                entity_ecf::bool_val(true),
            ));
            fields.push((
                entity_ecf::text("warning"),
                entity_ecf::text("tree has uncommitted changes that will be overwritten by checkout"),
            ));
        }
        fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let result = Entity::new("system/revision/checkout-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Merge (§4.3.4)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_merge(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let mp = decode_merge_params(&ctx.params.data)?;
        let prefix = mp.prefix;
        let remote_version = mp.remote_version;
        let strategy = mp.strategy;
        let dry_run = mp.dry_run;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        let lock = self.get_prefix_lock(&prefix);
        let _guard = lock.lock().await;

        // W6/W7: load config for oscillation_depth and merge_order fallback
        let prefix_config = self.load_prefix_config(&ph);
        let merge_order = mp
            .merge_order
            .as_deref()
            .or_else(|| prefix_config.as_ref().map(|c| c.merge_order.as_str()))
            .unwrap_or(engine::DEFAULT_MERGE_ORDER);

        // Get local head
        let head_path = rev_head_path(&self.local_peer_id, &ph);
        let local_head = match self.location_index.get(&head_path) {
            Some(h) => h,
            None => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "no_head",
                    "no versions exist for this prefix",
                ));
            }
        };

        // Check relationship
        let rel = check_relationship(self.content_store.as_ref(), local_head, remote_version);

        match rel {
            Relationship::InSync => {
                return Ok(merge_status_result("already_in_sync", None, &[], 0, 0, &[]));
            }
            Relationship::Ahead => {
                return Ok(merge_status_result("already_ahead", None, &[], 0, 0, &[]));
            }
            Relationship::Behind => {
                if dry_run {
                    return Ok(merge_status_result("would_merge", Some(remote_version), &[], 0, 0, &[]));
                }
                // EXTENSION-REVISION v3.2 §4.4.4 (A.3) version-transcription
                // invariant: fast-forward MUST NOT diff against the live
                // tree. The baseline is the committed local-head trie, so
                // live-tree paths not in either version (in-flight writes
                // pending AV capture, untracked paths, prior app state) are
                // preserved. Captured BEFORE the head advance below.
                let local_head_bindings = self.get_version_bindings(local_head)?;
                // Fast-forward: just move head to remote
                self.location_index.set(&head_path, remote_version);
                // Also advance active branch pointer
                if let Some(branch_name) = self.read_active_branch(&ph) {
                    let branch_path = rev_branch_path(&self.local_peer_id, &ph, &branch_name);
                    self.location_index.set(&branch_path, remote_version);
                }
                // Apply remote bindings to tree
                let remote_bindings = self.get_version_bindings(remote_version)?;
                let ff_warnings = self.apply_snapshot_diff(&prefix, &local_head_bindings, &remote_bindings)
                    .map_err(|rejected| HandlerError::Internal(
                        format!("fast-forward binding rejected at {}", rejected),
                    ))?;

                return Ok(merge_status_result(
                    "fast_forward",
                    Some(remote_version),
                    &[],
                    0,
                    0,
                    &ff_warnings,
                ));
            }
            Relationship::Diverged => {
                // Full three-way merge below
            }
        }

        // Content-identity check: if local and remote have the same root trie, they're converged
        let local_entry = self.content_store.get(&local_head)
            .and_then(|e| decode_revision_entry(&e));
        let remote_entry = self.content_store.get(&remote_version)
            .and_then(|e| decode_revision_entry(&e));

        if let (Some(ref le), Some(ref re)) = (&local_entry, &remote_entry) {
            if le.root == re.root {
                return Ok(merge_status_result("converged_identical", None, &[], 0, 0, &[]));
            }
        }

        // Find common ancestor
        let ancestor_hash =
            find_common_ancestor(self.content_store.as_ref(), local_head, remote_version);

        // Get bindings via trie
        let local_bindings = self.get_version_bindings(local_head)?;
        let remote_bindings = self.get_version_bindings(remote_version)?;
        let ancestor_bindings = match ancestor_hash {
            Some(ah) => Some(self.get_version_bindings(ah)?),
            None => None,
        };

        // Apply merge ordering (deterministic mode normalizes sides by hash)
        let (norm_local, norm_remote, norm_local_ver, norm_remote_ver) =
            merge::normalize_merge_sides(
                &local_bindings,
                &remote_bindings,
                local_head,
                remote_version,
                merge_order,
            );

        // Perform merge
        let mut merge_result = merge_snapshots(
            ancestor_bindings.as_ref(),
            norm_local,
            norm_remote,
            &prefix,
            strategy.as_deref(),
            self.content_store.as_ref(),
            self.location_index.as_ref(),
            norm_local_ver,
            norm_remote_ver,
            &self.local_peer_id,
        );

        // R4: fold additional_bindings (e.g. KeepBoth) into merged bindings
        for (path, hash) in merge_result.additional_bindings.drain(..) {
            merge_result.merged_bindings.insert(path, hash);
        }

        if dry_run {
            let dry_status = if merge_result.conflicts.is_empty() {
                "would_merge"
            } else {
                "would_conflict"
            };
            let conflict_paths: Vec<String> = merge_result.conflicts.iter()
                .map(|c| c.path.clone()).collect();
            return Ok(merge_status_result(
                dry_status,
                None,
                &conflict_paths,
                merge_result.merged_bindings.len(),
                merge_result.deletions.len(),
                &[],
            ));
        }

        // Build trie from merged bindings before applying — the merge version
        // is created and head advanced BEFORE bindings land, so auto-version
        // intermediates produced during binding application descend from the
        // merge version rather than orphaning (PROPOSAL-REVISION-AUTO-VERSION-FIX
        // §6A.1).
        let merged_root = trie::build_trie(
            self.content_store.as_ref(),
            &merge_result.merged_bindings,
        )
        .map_err(HandlerError::Internal)?;

        // Oscillation detection
        // W6: oscillation_depth from config, clamped to min 2
        let osc_depth = prefix_config.as_ref()
            .and_then(|c| c.oscillation_depth)
            .map(|d| std::cmp::max(2, d as usize))
            .unwrap_or(8);
        if detect_oscillation(self.content_store.as_ref(), merged_root, local_head, osc_depth) {
            return Ok(merge_status_result("oscillation_detected", None, &[], 0, 0, &[]));
        }

        // Create merge version using RevisionEntryData
        let mut parents = vec![local_head, remote_version];
        trie::sorted_parents(&mut parents);

        let entry_data = RevisionEntryData {
            root: merged_root,
            parents,
        };
        let version_entity =
            build_revision_entry(&entry_data).map_err(HandlerError::Internal)?;
        let version_hash = self
            .content_store
            .put(version_entity)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // Advance head and active-branch BEFORE applying bindings (§6A
        // structural rule). The active-branch advance here also fixes a
        // pre-existing bug where merge left branches/{name} lagging head
        // (cherry-pick and revert already advanced it; merge did not).
        self.location_index.set(&head_path, version_hash);
        if let Some(branch_name) = self.read_active_branch(&ph) {
            let branch_path = rev_branch_path(&self.local_peer_id, &ph, &branch_name);
            self.location_index.set(&branch_path, version_hash);
        }

        // Apply merged state to tree
        let current_bindings = self.compute_snapshot_bindings(&prefix);
        let mut cascade_warnings = self.apply_snapshot_diff(
            &prefix, &current_bindings, &merge_result.merged_bindings,
        ).map_err(|rejected| HandlerError::Internal(
            format!("merge binding rejected at {}", rejected),
        ))?;

        // Apply deletions (peer-qualified tree paths)
        let del_ctx = ExecutionContext::default();
        for path in &merge_result.deletions {
            let full_path = format!("{}{}", self.qualify_tree_prefix(&prefix), path);
            let (_removed, cascade) =
                self.location_index.remove_with_context(&full_path, del_ctx.clone());
            collect_cascade_warnings(&cascade, &full_path, &mut cascade_warnings)
                .map_err(|rejected| HandlerError::Internal(
                    format!("merge deletion rejected at {}", rejected),
                ))?;
        }

        // Store conflicts (excluded path — ordering irrelevant for auto-version)
        for conflict in &merge_result.conflicts {
            store_conflict(
                self.content_store.as_ref(),
                self.location_index.as_ref(),
                &ph,
                conflict,
                local_head,
                remote_version,
                &self.local_peer_id,
            )
            .map_err(HandlerError::Internal)?;
        }

        let conflict_paths: Vec<String> = merge_result.conflicts.iter()
            .map(|c| c.path.clone()).collect();
        let status = if !conflict_paths.is_empty() {
            "merged_with_conflicts"
        } else {
            "merged"
        };

        Ok(merge_status_result(
            status,
            Some(version_hash),
            &conflict_paths,
            merge_result.merged_bindings.len(),
            merge_result.deletions.len(),
            &cascade_warnings,
        ))
    }
}

// ---------------------------------------------------------------------------
// Resolve (§4.3.5)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_resolve(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (prefix, path, resolved_hash) = decode_resolve_params(&ctx.params.data)?;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        let conflict_path = rev_conflict_path(&self.local_peer_id, &ph, &path);
        if self.location_index.get(&conflict_path).is_none() {
            return Ok(error_result(
                STATUS_NOT_FOUND,
                "no_conflict",
                &format!("no conflict at path '{}'", path),
            ));
        }

        let full_path = format!("{}{}", self.qualify_tree_prefix(&prefix), path);

        if let Some(hash) = resolved_hash {
            // R2: verify resolved entity exists in content store
            if !self.content_store.has(&hash) {
                return Ok(error_result(
                    STATUS_NOT_FOUND,
                    "resolved_not_found",
                    "resolved entity hash not found in content store",
                ));
            }
            self.location_index.set(&full_path, hash);
        } else {
            // R2: resolve-by-deletion — unbind the path
            self.location_index.remove(&full_path);
        }

        // Remove conflict entry
        self.location_index.remove(&conflict_path);

        // R5: count remaining conflicts for this prefix
        let remaining_prefix = rev_conflicts_prefix(&self.local_peer_id, &ph);
        let remaining_conflicts = self.location_index.list(&remaining_prefix).len();

        let mut fields = vec![
            (entity_ecf::text("path"), entity_ecf::text(&path)),
            (
                entity_ecf::text("remaining_conflicts"),
                entity_ecf::integer(remaining_conflicts as i64),
            ),
        ];
        if let Some(hash) = resolved_hash {
            fields.push((
                entity_ecf::text("resolved"),
                entity_ecf::Value::Bytes(hash.to_bytes().to_vec()),
            ));
        }
        fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let result = Entity::new("system/revision/resolve-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
            included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Diff (§4.3.13)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_diff(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (prefix, base_version, target_version) = decode_diff_params(&ctx.params.data)?;

        let _ = prefix; // prefix kept for API consistency

        let base_bindings = self.get_version_bindings(base_version)?;
        let target_bindings = self.get_version_bindings(target_version)?;

        // Compute diff using added/changed/removed maps + unchanged count
        let mut added = Vec::new();
        let mut changed = Vec::new();
        let mut removed = Vec::new();
        let mut unchanged: usize = 0;

        let mut all_paths: Vec<String> = Vec::new();
        for p in base_bindings.keys().chain(target_bindings.keys()) {
            if !all_paths.contains(p) {
                all_paths.push(p.clone());
            }
        }
        all_paths.sort();

        for path in &all_paths {
            let base_hash = base_bindings.get(path);
            let target_hash = target_bindings.get(path);

            match (base_hash, target_hash) {
                (None, Some(t)) => {
                    added.push((
                        entity_ecf::text(path),
                        entity_ecf::Value::Bytes(t.to_bytes().to_vec()),
                    ));
                }
                (Some(b), None) => {
                    removed.push((
                        entity_ecf::text(path),
                        entity_ecf::Value::Bytes(b.to_bytes().to_vec()),
                    ));
                }
                (Some(b), Some(t)) if b != t => {
                    changed.push((
                        entity_ecf::text(path),
                        entity_ecf::Value::Map(vec![
                            (
                                entity_ecf::text("base"),
                                entity_ecf::Value::Bytes(b.to_bytes().to_vec()),
                            ),
                            (
                                entity_ecf::text("target"),
                                entity_ecf::Value::Bytes(t.to_bytes().to_vec()),
                            ),
                        ]),
                    ));
                }
                (Some(_), Some(_)) => {
                    unchanged += 1;
                }
                _ => {}
            }
        }

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("added"),
                entity_ecf::Value::Map(added),
            ),
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(base_version.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("changed"),
                entity_ecf::Value::Map(changed),
            ),
            (
                entity_ecf::text("removed"),
                entity_ecf::Value::Map(removed),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(target_version.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("unchanged"),
                entity_ecf::integer(unchanged as i64),
            ),
        ]));
        let result = Entity::new("system/tree/diff", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
            included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Cherry-pick (§4.3.14)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_cherry_pick(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let vop = decode_version_op_params(&ctx.params.data)?;
        let prefix = vop.prefix;
        let version_hash = vop.version;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        let lock = self.get_prefix_lock(&prefix);
        let _guard = lock.lock().await;

        // Get the version to cherry-pick
        let version_entity = self.content_store.get(&version_hash).ok_or_else(|| {
            HandlerError::InvalidParams("version not found".into())
        })?;
        let entry = decode_revision_entry(&version_entity).ok_or_else(|| {
            HandlerError::InvalidParams("invalid revision entry".into())
        })?;

        // Need parent to compute diff
        if entry.parents.is_empty() {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "no_parent",
                "cannot cherry-pick initial version (no parents)",
            ));
        }

        // Per C7 (EXTENSION-REVISION v2.2 §4.4.15): parent selection
        let parent_hash = if let Some(specified) = vop.parent {
            // Validate that specified parent is in the version's parent list
            if !entry.parents.contains(&specified) {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_parent",
                    "specified parent is not in version's parent list",
                ));
            }
            specified
        } else if entry.parents.len() > 1 {
            // Merge version with multiple parents requires explicit parent selection
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "ambiguous_parent",
                "merge version has multiple parents — specify which parent to diff against",
            ));
        } else {
            entry.parents[0]
        };

        // Get local head
        let head_path = rev_head_path(&self.local_peer_id, &ph);
        let local_head = self.location_index.get(&head_path).ok_or_else(|| {
            HandlerError::InvalidParams("no head for this prefix".into())
        })?;

        // Three-way merge: ancestor = version's parent bindings, local = current, remote = version's bindings
        let ancestor_bindings = self.get_version_bindings(parent_hash)?;
        let local_bindings = self.get_version_bindings(local_head)?;
        let version_bindings = self.get_version_bindings(version_hash)?;

        let mut merge_result = merge_snapshots(
            Some(&ancestor_bindings),
            &local_bindings,
            &version_bindings,
            &prefix,
            None,
            self.content_store.as_ref(),
            self.location_index.as_ref(),
            local_head,
            version_hash,
            &self.local_peer_id,
        );

        // R4: fold additional_bindings into merged bindings
        for (path, hash) in merge_result.additional_bindings.drain(..) {
            merge_result.merged_bindings.insert(path, hash);
        }

        // Build trie from merged bindings and create new revision entry
        // BEFORE applying bindings (PROPOSAL-REVISION-AUTO-VERSION-FIX §6A.2).
        let merged_root = trie::build_trie(
            self.content_store.as_ref(),
            &merge_result.merged_bindings,
        )
        .map_err(HandlerError::Internal)?;

        let mut parents = vec![local_head];
        trie::sorted_parents(&mut parents);

        let entry_data = RevisionEntryData {
            root: merged_root,
            parents,
        };
        let ve = build_revision_entry(&entry_data).map_err(HandlerError::Internal)?;
        let new_vh = self
            .content_store
            .put(ve)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // Advance head and active-branch BEFORE applying bindings (§6A rule).
        self.location_index.set(&head_path, new_vh);
        if let Some(branch_name) = self.read_active_branch(&ph) {
            let branch_path = rev_branch_path(&self.local_peer_id, &ph, &branch_name);
            self.location_index.set(&branch_path, new_vh);
        }

        // Apply merged state to tree.
        let current_bindings = self.compute_snapshot_bindings(&prefix);
        let mut cascade_warnings = self.apply_snapshot_diff(
            &prefix, &current_bindings, &merge_result.merged_bindings,
        ).map_err(|rejected| HandlerError::Internal(
            format!("cherry-pick binding rejected at {}", rejected),
        ))?;
        let del_ctx = ExecutionContext::default();
        for path in &merge_result.deletions {
            let full_path = format!("{}{}", self.qualify_tree_prefix(&prefix), path);
            let (_removed, cascade) =
                self.location_index.remove_with_context(&full_path, del_ctx.clone());
            collect_cascade_warnings(&cascade, &full_path, &mut cascade_warnings)
                .map_err(|rejected| HandlerError::Internal(
                    format!("cherry-pick deletion rejected at {}", rejected),
                ))?;
        }
        for conflict in &merge_result.conflicts {
            store_conflict(
                self.content_store.as_ref(),
                self.location_index.as_ref(),
                &ph,
                conflict,
                local_head,
                version_hash,
                &self.local_peer_id,
            )
            .map_err(HandlerError::Internal)?;
        }

        let status = if merge_result.conflicts.is_empty() {
            "cherry_picked"
        } else {
            "cherry_picked_with_conflicts"
        };

        let mut fields = vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(version_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("status"), entity_ecf::text(status)),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(new_vh.to_bytes().to_vec()),
            ),
        ];
        if let Some(warnings_val) = encode_cascade_warnings(&cascade_warnings) {
            fields.push((entity_ecf::text("cascade_warnings"), warnings_val));
        }
        if !merge_result.conflicts.is_empty() {
            fields.push((
                entity_ecf::text("conflicts"),
                entity_ecf::integer(merge_result.conflicts.len() as i64),
            ));
        }
        fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let result = Entity::new("system/revision/cherry-pick-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Revert (§4.3.15)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_revert(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let vop = decode_version_op_params(&ctx.params.data)?;
        let prefix = vop.prefix;
        let version_hash = vop.version;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        let lock = self.get_prefix_lock(&prefix);
        let _guard = lock.lock().await;

        let version_entity = self.content_store.get(&version_hash).ok_or_else(|| {
            HandlerError::InvalidParams("version not found".into())
        })?;
        let entry = decode_revision_entry(&version_entity).ok_or_else(|| {
            HandlerError::InvalidParams("invalid revision entry".into())
        })?;

        if entry.parents.is_empty() {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "no_parent",
                "cannot revert initial version (no parents)",
            ));
        }

        // R1: parent selection — mirror cherry-pick validation
        let parent_hash = if let Some(specified) = vop.parent {
            if !entry.parents.contains(&specified) {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_parent",
                    "specified parent is not in version's parent list",
                ));
            }
            specified
        } else if entry.parents.len() > 1 {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "ambiguous_parent",
                "merge version has multiple parents — specify which parent to diff against",
            ));
        } else {
            entry.parents[0]
        };

        let head_path = rev_head_path(&self.local_peer_id, &ph);
        let local_head = self.location_index.get(&head_path).ok_or_else(|| {
            HandlerError::InvalidParams("no head for this prefix".into())
        })?;
        let ancestor_bindings = self.get_version_bindings(version_hash)?;
        let local_bindings = self.get_version_bindings(local_head)?;
        let parent_bindings_raw = self.get_version_bindings(parent_hash)?;

        // EXTENSION-REVISION v3.1 §4.4.4 Amendment 3 + cross-impl
        // absorption (Rust SPEC-AMBIGUITIES Q2 → validator
        // `revert_file_removed` FAIL). Revert swaps merge roles —
        // ancestor = V_revert (the version being undone), remote = V_target
        // (the parent we're restoring to). Under v3.1 absence-is-preserve
        // semantics, paths V_revert added (present in ancestor, absent
        // from remote) would be preserved instead of unbound — the bug.
        // Fix: augment the remote view (V_target's bindings) with the
        // canonical deletion marker at every path V_revert added. The
        // merge classifier then sees "remote = marker" (intentional
        // delete signal) and routes the path through deletion_resolution.
        // Parallels Go's `revert.go::augmentTrieWithDeletionMarkers`.
        let parent_bindings = augment_bindings_with_markers(
            parent_bindings_raw,
            &ancestor_bindings,
            self.content_store.as_ref(),
        );

        let mut merge_result = merge_snapshots(
            Some(&ancestor_bindings),
            &local_bindings,
            &parent_bindings,
            &prefix,
            None,
            self.content_store.as_ref(),
            self.location_index.as_ref(),
            local_head,
            version_hash,
            &self.local_peer_id,
        );

        // R4: fold additional_bindings into merged bindings
        for (path, hash) in merge_result.additional_bindings.drain(..) {
            merge_result.merged_bindings.insert(path, hash);
        }

        // Build trie from merged bindings and create new revision entry
        // BEFORE applying bindings (PROPOSAL-REVISION-AUTO-VERSION-FIX §6A.3).
        let merged_root = trie::build_trie(
            self.content_store.as_ref(),
            &merge_result.merged_bindings,
        )
        .map_err(HandlerError::Internal)?;

        let mut parents = vec![local_head];
        trie::sorted_parents(&mut parents);

        let entry_data = RevisionEntryData {
            root: merged_root,
            parents,
        };
        let ve = build_revision_entry(&entry_data).map_err(HandlerError::Internal)?;
        let new_vh = self
            .content_store
            .put(ve)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // Advance head and active-branch BEFORE applying bindings (§6A rule).
        self.location_index.set(&head_path, new_vh);
        if let Some(branch_name) = self.read_active_branch(&ph) {
            let branch_path = rev_branch_path(&self.local_peer_id, &ph, &branch_name);
            self.location_index.set(&branch_path, new_vh);
        }

        // Apply merged state to tree.
        let current_bindings = self.compute_snapshot_bindings(&prefix);
        let mut cascade_warnings = self.apply_snapshot_diff(
            &prefix, &current_bindings, &merge_result.merged_bindings,
        ).map_err(|rejected| HandlerError::Internal(
            format!("revert binding rejected at {}", rejected),
        ))?;
        let del_ctx = ExecutionContext::default();
        for path in &merge_result.deletions {
            let full_path = format!("{}{}", self.qualify_tree_prefix(&prefix), path);
            let (_removed, cascade) =
                self.location_index.remove_with_context(&full_path, del_ctx.clone());
            collect_cascade_warnings(&cascade, &full_path, &mut cascade_warnings)
                .map_err(|rejected| HandlerError::Internal(
                    format!("revert deletion rejected at {}", rejected),
                ))?;
        }
        for conflict in &merge_result.conflicts {
            store_conflict(
                self.content_store.as_ref(),
                self.location_index.as_ref(),
                &ph,
                conflict,
                local_head,
                version_hash,
                &self.local_peer_id,
            )
            .map_err(HandlerError::Internal)?;
        }

        let status = if merge_result.conflicts.is_empty() {
            "reverted"
        } else {
            "reverted_with_conflicts"
        };

        let mut fields = vec![
            (
                entity_ecf::text("reverted"),
                entity_ecf::Value::Bytes(version_hash.to_bytes().to_vec()),
            ),
            (entity_ecf::text("status"), entity_ecf::text(status)),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(new_vh.to_bytes().to_vec()),
            ),
        ];
        if let Some(warnings_val) = encode_cascade_warnings(&cascade_warnings) {
            fields.push((entity_ecf::text("cascade_warnings"), warnings_val));
        }
        if !merge_result.conflicts.is_empty() {
            fields.push((
                entity_ecf::text("conflicts"),
                entity_ecf::integer(merge_result.conflicts.len() as i64),
            ));
        }
        fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let result = Entity::new("system/revision/revert-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Fetch (§4.3.6) — read local head + walk history
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_fetch(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (prefix, depth, since) = decode_log_params(&ctx.params.data)?;
        let effective_depth = depth.unwrap_or(50);

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);
        let head_path = rev_head_path(&self.local_peer_id, &ph);
        let head_hash = match self.location_index.get(&head_path) {
            Some(h) => h,
            None => {
                // No head — nothing to fetch
                let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("has_more"),
                        entity_ecf::bool_val(false),
                    ),
                    (
                        entity_ecf::text("versions"),
                        entity_ecf::Value::Array(vec![]),
                    ),
                ]));
                let result = Entity::new("system/revision/fetch-result", data)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                let envelope = build_envelope_result(result, std::collections::HashMap::new());
                return Ok(HandlerResult::ok(envelope));
            }
        };

        // W2: walk history with since stop-point
        let history = walk_history(
            self.content_store.as_ref(),
            head_hash,
            effective_depth + 1,
            since,
        );
        let has_more = history.len() > effective_depth;

        // Collect version entities + root trie node entities in included
        let mut included = std::collections::HashMap::new();
        let mut version_hash_values = Vec::new();
        for h in history.iter().take(effective_depth) {
            version_hash_values.push(entity_ecf::Value::Bytes(h.to_bytes().to_vec()));
            if let Some(entity) = self.content_store.get(h) {
                // Include the root trie node as well
                if let Some(entry) = decode_revision_entry(&entity) {
                    if let Some(root_entity) = self.content_store.get(&entry.root) {
                        included.insert(entry.root, root_entity);
                    }
                }
                included.insert(*h, entity);
            }
        }

        let mut fields = vec![
            (
                entity_ecf::text("has_more"),
                entity_ecf::bool_val(has_more),
            ),
            (
                entity_ecf::text("head"),
                entity_ecf::Value::Bytes(head_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("versions"),
                entity_ecf::Value::Array(version_hash_values),
            ),
        ];
        fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let result = Entity::new("system/revision/fetch-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let envelope = build_envelope_result(result, included);
        Ok(HandlerResult::ok(envelope))
    }
}

// ---------------------------------------------------------------------------
// Push (§4.3.8)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_push(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (prefix, remote) = decode_push_params(&ctx.params.data)?;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        let head_path = rev_head_path(&self.local_peer_id, &ph);
        let local_head = match self.location_index.get(&head_path) {
            Some(h) => h,
            None => {
                return Ok(push_status_result("nothing_to_push", 0));
            }
        };

        let remote_hex = peer_remote_hex(&remote)?;
        let remote_head_path = rev_remote_path(&self.local_peer_id, &ph, &remote_hex);
        let remote_head = self.location_index.get(&remote_head_path);

        if let Some(rh) = remote_head {
            let rel = check_relationship(self.content_store.as_ref(), rh, local_head);
            match rel {
                Relationship::InSync => {
                    return Ok(push_status_result("nothing_to_push", 0));
                }
                Relationship::Ahead => {
                    return Ok(push_status_result("rejected_behind", 0));
                }
                Relationship::Diverged => {
                    // R3: MUST reject diverged — caller must pull/merge first
                    return Ok(push_status_result("diverged", 0));
                }
                Relationship::Behind => {
                    // Local is ahead of remote — fall through to push
                }
            }
        }

        // Count versions to push
        let versions = if let Some(rh) = remote_head {
            let history = walk_history(self.content_store.as_ref(), local_head, 1000, Some(rh));
            history.len()
        } else {
            let history = walk_history(self.content_store.as_ref(), local_head, 1000, None);
            history.len()
        };

        // Update remote head pointer
        self.location_index.set(&remote_head_path, local_head);

        Ok(push_status_result("pushed", versions))
    }
}

// ---------------------------------------------------------------------------
// Fetch-entities (new operation)
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_fetch_entities(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let (prefix, snapshot_root, hashes) = decode_fetch_entities_params(&ctx.params.data)?;

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        // I3: verify snapshot root is reachable from this prefix's head
        let head_path = rev_head_path(&self.local_peer_id, &ph);
        if let Some(head) = self.location_index.get(&head_path) {
            let history = walk_history(self.content_store.as_ref(), head, 1000, None);
            let root_valid = history.iter().any(|vh| {
                self.content_store.get(vh)
                    .and_then(|e| decode_revision_entry(&e))
                    .map(|entry| entry.root == snapshot_root)
                    .unwrap_or(false)
            });
            if !root_valid {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "snapshot_not_found",
                    "snapshot root not found in prefix's version history",
                ));
            }
        } else {
            return Ok(error_result(
                STATUS_NOT_FOUND,
                "no_head",
                "no versions exist for this prefix",
            ));
        }

        // Collect all valid hashes from the trie
        let valid_hashes = trie::collect_all_hashes(self.content_store.as_ref(), snapshot_root);

        let mut found = Vec::new();
        let mut missing = Vec::new();
        let mut included = std::collections::HashMap::new();

        for h in &hashes {
            if valid_hashes.contains(h) {
                if let Some(entity) = self.content_store.get(h) {
                    found.push(entity_ecf::Value::Bytes(h.to_bytes().to_vec()));
                    included.insert(*h, entity);
                } else {
                    missing.push(entity_ecf::Value::Bytes(h.to_bytes().to_vec()));
                }
            } else {
                missing.push(entity_ecf::Value::Bytes(h.to_bytes().to_vec()));
            }
        }

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("found"),
                entity_ecf::Value::Array(found),
            ),
            (
                entity_ecf::text("missing"),
                entity_ecf::Value::Array(missing),
            ),
        ]));
        let result = Entity::new("system/revision/fetch-entities-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let envelope = build_envelope_result(result, included);
        Ok(HandlerResult::ok(envelope))
    }
}

// ---------------------------------------------------------------------------
// Fetch-diff (§4.4.19) — incremental closure transport rooted at base.
// EXTENSION-REVISION v3.4. Replaces the withdrawn tree:extract.since.
// ---------------------------------------------------------------------------

impl RevisionHandler {
    async fn handle_fetch_diff(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // EXTENSION-REVISION v3.6 §4.4.19: fetch-diff is unambiguously
        // executor-local under any dispatch shape — the implicit target is
        // the executor peer's current head, the base lookup is in the
        // executor's content store. Cross-peer dispatch is well-defined and
        // implementations MUST NOT reject it. Both call patterns are valid:
        // local follow chain (cross-peer dispatched at the leader) and
        // cross-peer pull reconcile (caller pulls executor's diff for merge).
        // Shape B (single-dynamic-field, chain-expressible): target is the
        // handler peer's current head for `prefix`; caller supplies `base`
        // (the version they already have, or zero for full closure).
        let (prefix, base) = match decode_fetch_diff_params(&ctx.params.data) {
            Ok(p) => p,
            Err(_) => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "could not decode fetch-diff params",
                ));
            }
        };
        if prefix.is_empty() {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "prefix is required",
            ));
        }

        let abs_prefix = resolve_prefix(&prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);

        // Resolve local head → version entry → trie root (target).
        let head_path = rev_head_path(&self.local_peer_id, &ph);
        let head_hash = match self.location_index.get(&head_path) {
            Some(h) => h,
            None => {
                return Ok(error_result(
                    STATUS_NOT_FOUND,
                    "no_local_state",
                    &format!("no revision head bound for prefix: {}", abs_prefix),
                ));
            }
        };
        let target_root = match self.content_store.get(&head_hash)
            .and_then(|e| decode_revision_entry(&e))
        {
            Some(entry) => entry.root,
            None => {
                return Ok(error_result(
                    STATUS_INTERNAL_ERROR,
                    "internal_error",
                    "revision head version entry missing or undecodable",
                ));
            }
        };

        // Resolve base. Zero/absent → full closure (empty skip set).
        let mut skip: std::collections::HashSet<Hash> = std::collections::HashSet::new();
        if let Some(base_hash) = base {
            let base_entity = match self.content_store.get(&base_hash) {
                Some(e) => e,
                None => {
                    return Ok(error_result(
                        STATUS_NOT_FOUND,
                        "base_not_found",
                        "server does not have the specified base version; caller may retry with base unset (full closure)",
                    ));
                }
            };
            let base_root = match decode_revision_entry(&base_entity) {
                Some(entry) => entry.root,
                None => {
                    return Ok(error_result(
                        STATUS_BAD_REQUEST,
                        "base_not_a_version",
                        &format!("base hash does not resolve to a version entry: {}", base_hash),
                    ));
                }
            };
            trie::collect_reachable_hashes(
                self.content_store.as_ref(),
                base_root,
                &mut skip,
            );
        }

        // Walk target collecting the diff closure.
        let mut included_btree: std::collections::BTreeMap<Hash, Entity> =
            std::collections::BTreeMap::new();
        trie::collect_trie_entities_except(
            self.content_store.as_ref(),
            target_root,
            &skip,
            &mut included_btree,
        );

        // The envelope root is a thin snapshot wrapper pointing at the
        // target trie root (matches tree:extract's wire shape).
        let snapshot_ent = build_snapshot_pointer(target_root)?;
        let included: std::collections::HashMap<Hash, Entity> =
            included_btree.into_iter().collect();
        let envelope = build_envelope_result(snapshot_ent, included);
        Ok(HandlerResult::ok(envelope))
    }
}

fn build_snapshot_pointer(root: Hash) -> Result<Entity, HandlerError> {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("root"),
        entity_ecf::Value::Bytes(root.to_bytes().to_vec()),
    )]));
    Entity::new(entity_types::TYPE_TREE_SNAPSHOT, data)
        .map_err(|e| HandlerError::Internal(e.to_string()))
}

fn decode_fetch_diff_params(data: &[u8]) -> Result<(String, Option<Hash>), HandlerError> {
    if data.is_empty() {
        return Err(HandlerError::InvalidParams("params empty".into()));
    }
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut base = None;
    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("base") => {
                if let ciborium::Value::Bytes(b) = v {
                    if !b.is_empty() {
                        base = Hash::from_bytes(b).ok();
                    }
                }
            }
            _ => {}
        }
    }
    let prefix = prefix.unwrap_or_default();
    Ok((prefix, base))
}

// ---------------------------------------------------------------------------
// Pull (§4.4.8) — convenience composition: cross-peer fetch + iterative
// fetch-entities trie walk + local merge. Folds the multi-round closure
// transport into a single op so the operation is chain-expressible
// (continuation transforms cannot iterate on the caller side; the
// iteration moves inside the handler).
// ---------------------------------------------------------------------------

const PULL_MAX_ROUNDS: usize = 32;

impl RevisionHandler {
    async fn handle_pull(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let params = decode_fetch_params(&ctx.params.data)?;
        if params.prefix.is_empty() {
            return Ok(error_result(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "prefix is required",
            ));
        }
        let remote = match params.remote.as_deref() {
            Some(r) if !r.is_empty() => r.to_string(),
            _ => {
                return Ok(error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "remote peer-id is required for pull",
                ));
            }
        };
        let local_prefix = resolve_prefix(&params.prefix, &self.local_peer_id);

        let execute_fn = match ctx.execute_fn.as_ref() {
            Some(f) => f.clone(),
            None => {
                return Ok(error_result(
                    STATUS_INTERNAL_ERROR,
                    "internal_error",
                    "handler context missing execute_fn (required for outbound cross-peer dispatch)",
                ));
            }
        };

        // 1. Outbound fetch against the remote.
        let remote_uri = format!("entity://{}/system/revision", remote);
        let remote_pull_prefix = params
            .remote_prefix
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| params.prefix.clone());

        let remote_fetch_params_entity = build_fetch_params_entity(
            &remote_pull_prefix,
            params.remote_prefix.as_deref(),
            params.since,
            params.depth,
        )?;

        let fetch_resp = match execute_fn(
            remote_uri.clone(),
            "fetch".to_string(),
            remote_fetch_params_entity,
            ExecuteOptions::default(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                return Ok(error_result(
                    STATUS_BAD_GATEWAY,
                    "remote_fetch_failed",
                    &format!("revision/fetch on {}: {}", remote, e),
                ));
            }
        };
        if fetch_resp.status >= 400 {
            return Ok(error_result(
                STATUS_BAD_GATEWAY,
                "remote_fetch_failed",
                &format!("revision/fetch on {}: status={}", remote, fetch_resp.status),
            ));
        }
        if fetch_resp.result.entity_type != entity_types::TYPE_ENVELOPE {
            return Ok(error_result(
                STATUS_BAD_GATEWAY,
                "remote_fetch_failed",
                &format!(
                    "expected {} from remote fetch; got {}",
                    entity_types::TYPE_ENVELOPE,
                    fetch_resp.result.entity_type
                ),
            ));
        }

        // 2. Ingest envelope.included → local store. Extract head from
        //    fetch-result inside envelope.root.
        let (fetch_root, fetch_included) = match decode_envelope(&fetch_resp.result.data) {
            Ok(p) => p,
            Err(e) => {
                return Ok(error_result(
                    STATUS_BAD_GATEWAY,
                    "remote_fetch_failed",
                    &format!("decode remote fetch envelope: {}", e),
                ));
            }
        };
        for (_, ent) in fetch_included {
            // Ignore individual put failures — content-addressed, idempotent;
            // missing entities surface as a closure gap in the next walk round
            // and produce a refetch.
            let _ = self.content_store.put(ent);
        }
        let head = match decode_fetch_result_head(&fetch_root.data) {
            Some(h) if !h.is_zero() => h,
            Some(_) | None => {
                return Ok(error_result(
                    STATUS_INTERNAL_ERROR,
                    "remote_empty",
                    &format!("remote {} has no versions at prefix {}", remote, local_prefix),
                ));
            }
        };

        // 3. Walk the remote's trie locally; iteratively fetch-entities
        //    until the closure is complete or we hit the round cap.
        let version_entity = match self.content_store.get(&head) {
            Some(e) => e,
            None => {
                return Ok(error_result(
                    STATUS_INTERNAL_ERROR,
                    "internal_error",
                    "version entity missing after fetch ingest",
                ));
            }
        };
        let root = match decode_revision_entry(&version_entity) {
            Some(e) => e.root,
            None => {
                return Ok(error_result(
                    STATUS_INTERNAL_ERROR,
                    "internal_error",
                    "decode fetched version entry failed",
                ));
            }
        };

        for round in 0..PULL_MAX_ROUNDS {
            let missing = collect_missing_pull_hashes(self.content_store.as_ref(), root);
            if missing.is_empty() {
                break;
            }
            let fe_params = build_fetch_entities_params_entity(&remote_pull_prefix, root, &missing)?;
            let fe_resp = match execute_fn(
                remote_uri.clone(),
                "fetch-entities".to_string(),
                fe_params,
                ExecuteOptions::default(),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    return Ok(error_result(
                        STATUS_BAD_GATEWAY,
                        "remote_fetch_failed",
                        &format!(
                            "revision/fetch-entities round {} on {}: {}",
                            round + 1,
                            remote,
                            e
                        ),
                    ));
                }
            };
            if fe_resp.status >= 400 {
                return Ok(error_result(
                    STATUS_BAD_GATEWAY,
                    "remote_fetch_failed",
                    &format!(
                        "revision/fetch-entities round {} on {}: status={}",
                        round + 1,
                        remote,
                        fe_resp.status
                    ),
                ));
            }
            if fe_resp.result.entity_type != entity_types::TYPE_ENVELOPE {
                break;
            }
            let (_root, included) = match decode_envelope(&fe_resp.result.data) {
                Ok(p) => p,
                Err(_) => break,
            };
            let mut ingested = 0usize;
            for (_, ent) in included {
                if self.content_store.put(ent).is_ok() {
                    ingested += 1;
                }
            }
            if ingested == 0 {
                // Remote reports nothing else available; stop to avoid
                // infinite loop on an inconsistent remote.
                break;
            }
        }

        // 4. Local merge against the freshly-fetched remote head.
        let merge_params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text(&local_prefix)),
            (
                entity_ecf::text("remote_version"),
                entity_ecf::Value::Bytes(head.to_bytes().to_vec()),
            ),
        ]));
        let merge_params_entity =
            Entity::new("system/revision/merge-params", merge_params_data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let merge_ctx = clone_ctx_with(ctx, merge_params_entity, "merge".to_string());
        self.handle_merge(&merge_ctx).await
    }
}

/// Encode a `system/revision/fetch-params` entity for outbound pull dispatch.
fn build_fetch_params_entity(
    prefix: &str,
    remote_prefix: Option<&str>,
    since: Option<Hash>,
    depth: Option<usize>,
) -> Result<Entity, HandlerError> {
    let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();
    if let Some(d) = depth {
        fields.push((entity_ecf::text("depth"), entity_ecf::integer(d as i64)));
    }
    fields.push((entity_ecf::text("prefix"), entity_ecf::text(prefix)));
    if let Some(rp) = remote_prefix {
        if !rp.is_empty() {
            fields.push((entity_ecf::text("remote_prefix"), entity_ecf::text(rp)));
        }
    }
    if let Some(h) = since {
        fields.push((
            entity_ecf::text("since"),
            entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    Entity::new("system/revision/fetch-params", data)
        .map_err(|e| HandlerError::Internal(e.to_string()))
}

/// Encode a `system/revision/fetch-entities-params` entity for outbound pull dispatch.
fn build_fetch_entities_params_entity(
    prefix: &str,
    snapshot: Hash,
    hashes: &[Hash],
) -> Result<Entity, HandlerError> {
    let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = vec![
        (
            entity_ecf::text("hashes"),
            entity_ecf::Value::Array(
                hashes
                    .iter()
                    .map(|h| entity_ecf::Value::Bytes(h.to_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (entity_ecf::text("prefix"), entity_ecf::text(prefix)),
        (
            entity_ecf::text("snapshot"),
            entity_ecf::Value::Bytes(snapshot.to_bytes().to_vec()),
        ),
    ];
    fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    Entity::new("system/revision/fetch-entities-params", data)
        .map_err(|e| HandlerError::Internal(e.to_string()))
}

/// Decode an envelope's CBOR data into (root, included) pairs. The result
/// entity at `root` is reconstructed from the inline `{type, data, content_hash}`
/// shape produced by `build_envelope_result`/`entity_to_inline`.
fn decode_envelope(
    data: &[u8],
) -> Result<(Entity, Vec<(Hash, Entity)>), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::Internal(format!("envelope decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::Internal("envelope not a map".into()))?;

    let mut root = None;
    let mut included: Vec<(Hash, Entity)> = Vec::new();
    for (k, v) in map {
        match k.as_text() {
            Some("root") => {
                root = Some(inline_to_entity(v)?);
            }
            Some("included") => {
                if let Some(inc_map) = v.as_map() {
                    for (ik, iv) in inc_map {
                        let hash_bytes = ik
                            .as_bytes()
                            .ok_or_else(|| HandlerError::Internal(
                                "envelope included key not bytes".into(),
                            ))?;
                        let h = Hash::from_bytes(hash_bytes)
                            .map_err(|e| HandlerError::Internal(e.to_string()))?;
                        included.push((h, inline_to_entity(iv)?));
                    }
                }
            }
            _ => {}
        }
    }
    let root = root.ok_or_else(|| HandlerError::Internal("envelope missing root".into()))?;
    Ok((root, included))
}

/// Reconstruct an Entity from the inline `{content_hash, data, type}` CBOR
/// shape produced by `entity_to_inline`.
fn inline_to_entity(v: &ciborium::Value) -> Result<Entity, HandlerError> {
    let m = v
        .as_map()
        .ok_or_else(|| HandlerError::Internal("inline entity not a map".into()))?;
    let mut entity_type: Option<String> = None;
    let mut data_value: Option<&ciborium::Value> = None;
    for (k, vv) in m {
        match k.as_text() {
            Some("type") => entity_type = vv.as_text().map(|s| s.to_string()),
            Some("data") => data_value = Some(vv),
            _ => {}
        }
    }
    let entity_type =
        entity_type.ok_or_else(|| HandlerError::Internal("inline entity missing type".into()))?;
    let data_value =
        data_value.ok_or_else(|| HandlerError::Internal("inline entity missing data".into()))?;
    let mut data_bytes = Vec::new();
    ciborium::into_writer(data_value, &mut data_bytes)
        .map_err(|e| HandlerError::Internal(format!("inline data encode: {}", e)))?;
    Entity::new(&entity_type, data_bytes)
        .map_err(|e| HandlerError::Internal(e.to_string()))
}

/// Decode `head` from a `system/revision/fetch-result` entity's CBOR data.
fn decode_fetch_result_head(data: &[u8]) -> Option<Hash> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("head") {
            if let ciborium::Value::Bytes(b) = v {
                return Hash::from_bytes(b).ok();
            }
        }
    }
    None
}

/// Walk the trie at `root`, collecting trie-node hashes the local store
/// doesn't have AND leaf binding hashes the local store doesn't have.
/// Mirrors Go's `collectMissingPullHashes` (entity-core-go/ext/revision/pull.go).
fn collect_missing_pull_hashes(store: &dyn ContentStore, root: Hash) -> Vec<Hash> {
    if root.is_zero() {
        return Vec::new();
    }
    let mut seen: std::collections::HashSet<Hash> = std::collections::HashSet::new();
    let mut missing: Vec<Hash> = Vec::new();
    fn visit(
        store: &dyn ContentStore,
        h: Hash,
        seen: &mut std::collections::HashSet<Hash>,
        missing: &mut Vec<Hash>,
    ) {
        if h.is_zero() || !seen.insert(h) {
            return;
        }
        let node_ent = match store.get(&h) {
            Some(e) => e,
            None => {
                // Trie node not local yet — request it.
                missing.push(h);
                return;
            }
        };
        if node_ent.entity_type != trie::TYPE_TREE_SNAPSHOT_NODE {
            // Leaf data entity already present; nothing to walk.
            return;
        }
        let nd = match trie::SnapshotNodeData::from_cbor(&node_ent.data) {
            Some(d) => d,
            None => return,
        };
        // HAMT v4.0 walk: each entry in `data` is either a bucket of
        // [key, value_hash] tuples (leaf-level) or a link to a sub-node.
        // Buckets contribute value-entity hashes; links recurse.
        for entry in &nd.data {
            match entry {
                trie::Entry::Bucket(tuples) => {
                    for (_, value_hash) in tuples {
                        if !value_hash.is_zero() && store.get(value_hash).is_none() {
                            missing.push(*value_hash);
                        }
                    }
                }
                trie::Entry::Link(child) => {
                    visit(store, *child, seen, missing);
                }
            }
        }
    }
    visit(store, root, &mut seen, &mut missing);
    missing
}

/// Construct a synthetic HandlerContext for an internal handler-to-handler
/// invocation (e.g., pull invoking merge). All cap/auth/identity fields are
/// inherited from the parent context; only `params` and `operation` change.
fn clone_ctx_with(parent: &HandlerContext, params: Entity, operation: String) -> HandlerContext {
    HandlerContext {
        handler_grant: parent.handler_grant.clone(),
        caller_capability: parent.caller_capability.clone(),
        execute: parent.execute.clone(),
        params,
        pattern: parent.pattern.clone(),
        suffix: parent.suffix.clone(),
        resource_target: parent.resource_target.clone(),
        author: parent.author,
        session_peer_id: parent.session_peer_id.clone(),
        request_id: parent.request_id.clone(),
        operation,
        execute_fn: parent.execute_fn.clone(),
        included: parent.included.clone(),
        matching_grant: parent.matching_grant.clone(),
        capability_hash: parent.capability_hash,
        handler_grant_hash: parent.handler_grant_hash,
        bounds: parent.bounds.clone(),
        // PROPOSAL-CONVERGENT-MIRRORING §2.3 D4: propagate the parent's
        // external-origin flag so receiver-local-op rejection still fires
        // for inner ops dispatched from a wire-originated chain.
        is_external: parent.is_external,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

impl RevisionHandler {
    /// Read active branch name for a prefix hash.
    fn read_active_branch(&self, ph: &str) -> Option<String> {
        let ab_path = rev_active_branch_path(&self.local_peer_id, ph);
        let hash = self.location_index.get(&ab_path)?;
        let entity = self.content_store.get(&hash)?;
        let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
        let map = val.as_map()?;
        for (k, v) in map {
            if k.as_text() == Some("name") {
                return v.as_text().map(|s| s.to_string());
            }
        }
        None
    }

    /// Look up the effective auto-version + checkout policy for a prefix.
    /// Direct O(1) lookup at `/{pid}/system/revision/{ph}/config`.
    ///
    /// `ph` is the prefix hash (call `prefix_hash(resolve_prefix(...))` first).
    fn load_prefix_config(&self, ph: &str) -> Option<engine::RevisionConfig> {
        let cfg_path = rev_config_path(&self.local_peer_id, ph);
        let hash = self.location_index.get(&cfg_path)?;
        let entity = self.content_store.get(&hash)?;
        engine::decode_revision_config(&entity.data)
    }

    fn auto_version_policy_for(&self, prefix: &str) -> (bool, String) {
        let abs_prefix = resolve_prefix(prefix, &self.local_peer_id);
        let ph = prefix_hash(&abs_prefix);
        if let Some(cfg) = self.load_prefix_config(&ph) {
            (cfg.auto_version, cfg.checkout_under_auto_version)
        } else {
            (false, engine::DEFAULT_CHECKOUT_POLICY.to_string())
        }
    }

    /// Set the active branch name for a prefix hash.
    fn set_active_branch(&self, ph: &str, name: &str) {
        let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "name" => entity_ecf::text(name)
        });
        if let Ok(entity) = Entity::new("system/revision/active-branch", data) {
            if let Ok(hash) = self.content_store.put(entity) {
                let ab_path = rev_active_branch_path(&self.local_peer_id, ph);
                self.location_index.set(&ab_path, hash);
            }
        }
    }

    /// Compute snapshot bindings for a prefix from the current tree (relative paths).
    ///
    /// Accepts a bare prefix (e.g., `"data/"`) — qualifies idempotently.
    fn compute_snapshot_bindings(&self, prefix: &str) -> BTreeMap<String, Hash> {
        snapshot_bindings_from_tree(self.location_index.as_ref(), prefix, &self.local_peer_id)
    }

    /// Get version's bindings from store via trie.
    ///
    /// Loads revision entry -> gets root hash -> flattens trie to bindings.
    fn get_version_bindings(
        &self,
        version_hash: Hash,
    ) -> Result<BTreeMap<String, Hash>, HandlerError> {
        let version_entity = self.content_store.get(&version_hash).ok_or_else(|| {
            HandlerError::Internal(format!("version entity not found: {}", version_hash))
        })?;
        let entry = decode_revision_entry(&version_entity).ok_or_else(|| {
            HandlerError::Internal("failed to decode revision entry".into())
        })?;

        Ok(trie::collect_all_bindings(
            self.content_store.as_ref(),
            entry.root,
            "",
        ))
    }

    /// Apply diff between current and target bindings to the tree.
    ///
    /// Accepts a bare prefix (e.g., `"data/"`) and qualifies it with `local_peer_id`
    /// for tree operations. Idempotent — already-qualified prefixes are not double-qualified.
    ///
    /// Uses `set_with_context`/`remove_with_context` so cascade consumers fire.
    /// Returns collected cascade warnings (207 halts where the binding still
    /// committed).  If a write is rejected (binding NOT committed), returns
    /// `Err(rejected_path)`.
    fn apply_snapshot_diff(
        &self,
        prefix: &str,
        current: &BTreeMap<String, Hash>,
        target: &BTreeMap<String, Hash>,
    ) -> Result<Vec<CascadeWarning>, String> {
        let tree_prefix = self.qualify_tree_prefix(prefix);
        let ctx = ExecutionContext::default();
        let mut warnings = Vec::new();
        // EXTENSION-REVISION v3.1 §4.4.4 deletion-marker apply translation:
        // when a path's bound entity in `target` is the canonical
        // deletion marker (NATIVE-TYPE-SYSTEM §4.9), the operation MUST
        // translate the binding to a live-tree unbind. Live-tree never
        // contains marker entities.
        let marker_hash = entity_entity::canonical_deletion_marker_hash();

        // Remove paths not in target, plus paths whose target binding
        // is the canonical deletion marker.
        for rel_path in current.keys() {
            let should_remove = !target.contains_key(rel_path)
                || target.get(rel_path) == Some(&marker_hash);
            if should_remove {
                let full_path = format!("{}{}", tree_prefix, rel_path);
                let (_removed, cascade) =
                    self.location_index.remove_with_context(&full_path, ctx.clone());
                collect_cascade_warnings(&cascade, &full_path, &mut warnings)?;
            }
        }
        // Set/update paths in target — skip deletion markers (handled above).
        for (rel_path, hash) in target {
            if *hash == marker_hash {
                continue;
            }
            let full_path = format!("{}{}", tree_prefix, rel_path);
            let cascade =
                self.location_index.set_with_context(&full_path, *hash, ctx.clone());
            collect_cascade_warnings(&cascade, &full_path, &mut warnings)?;
        }
        Ok(warnings)
    }
}

// ---------------------------------------------------------------------------
// Shared commit logic module
// ---------------------------------------------------------------------------

/// Augment `target` bindings with the canonical deletion marker at every
/// path present in `added_relative_to` but absent from `target`. Used by
/// operations that want to turn an additive-set difference into an
/// explicit deletion signal (currently: `revert`, per EXTENSION-REVISION
/// v3.1 §4.4.4 Amendment 3). Under v3.1 absence-is-preserve semantics,
/// the standard three-way merge would interpret "target absent at P" as
/// "no opinion" and preserve `local`'s binding — defeating the
/// caller's intent. Injecting markers makes those paths explicit
/// deletion signals, routing them correctly through the merge
/// classifier's deletion-vs-entity branch.
///
/// Idempotent: re-puts the canonical marker entity (same content hash);
/// no-op if `target` already has every path `added_relative_to` has.
fn augment_bindings_with_markers(
    target: BTreeMap<String, Hash>,
    added_relative_to: &BTreeMap<String, Hash>,
    content_store: &dyn ContentStore,
) -> BTreeMap<String, Hash> {
    let mut augmented = target;
    // Find paths in added_relative_to that aren't in target.
    let any_to_add = added_relative_to.keys().any(|p| !augmented.contains_key(p));
    if !any_to_add {
        return augmented;
    }
    // Ensure the canonical marker entity is in the content store.
    let _ = content_store.put(entity_entity::canonical_deletion_marker_entity());
    let marker_hash = entity_entity::canonical_deletion_marker_hash();
    for path in added_relative_to.keys() {
        augmented.entry(path.clone()).or_insert(marker_hash);
    }
    augmented
}

pub(crate) mod commit_logic {
    use super::*;

    /// Core commit logic shared by handler and engine.
    ///
    /// Snapshots the tree at `prefix`, builds a trie, creates a revision entry,
    /// updates head and active branch pointer.
    ///
    /// `prefix` is the bare prefix for version entity storage (interop).
    /// Tree data is looked up at `{local_peer_id}/{prefix}` (peer-qualified).
    ///
    /// Returns `(version_hash, root_hash, parent)`. `parent` is the prior
    /// HEAD of the returned version entry — `None` for first commit and
    /// for dedup short-circuits when the existing HEAD entry has no
    /// parents.
    pub fn perform_commit(
        content_store: &dyn ContentStore,
        location_index: &dyn LocationIndex,
        prefix: &str,
        local_peer_id: &str,
    ) -> Result<(Hash, Hash, Option<Hash>), String> {
        let abs_prefix = crate::resolve_prefix(prefix, local_peer_id);
        let ph = crate::prefix_hash(&abs_prefix);

        let raw_bindings = snapshot_bindings_from_tree(location_index, prefix, local_peer_id);

        // S2: apply exclude/exclude_types filters from config
        let bindings = {
            let cfg_path = crate::rev_config_path(local_peer_id, &ph);
            let config = location_index.get(&cfg_path).and_then(|hash| {
                let entity = content_store.get(&hash)?;
                crate::engine::decode_revision_config(&entity.data)
            });
            if let Some(ref cfg) = config {
                let mut filtered = BTreeMap::new();
                for (path, hash) in &raw_bindings {
                    if cfg.exclude.iter().any(|pat| crate::engine::exclude_pattern_matches(pat, path)) {
                        continue;
                    }
                    if !cfg.exclude_types.is_empty() {
                        if let Some(entity) = content_store.get(hash) {
                            if cfg.exclude_types.iter().any(|t| t == &entity.entity_type) {
                                continue;
                            }
                        }
                    }
                    filtered.insert(path.clone(), *hash);
                }
                filtered
            } else {
                raw_bindings
            }
        };

        // Get current head as parent
        let head_path = crate::rev_head_path(local_peer_id, &ph);
        let current_head = location_index.get(&head_path);

        // EXTENSION-REVISION v3.1 §6.1 + v3.3 D3 deletion-marker emission.
        // Every path bound in the parent version's trie MUST have an
        // explicit entry in the new version's trie: a live binding if
        // still bound, or the canonical deletion marker (NATIVE-TYPE-
        // SYSTEM §4.9) if unbound between parent and commit. Markers are
        // canonical (same hash everywhere) so deletion-vs-deletion is
        // not divergent; carry-forward is automatic via the trie's
        // content-addressed dedup. v3.3 D3: augmentation MUST run BEFORE
        // the §6.2 dedup-against-prior-head check below.
        let bindings = if let Some(parent_hash) = current_head {
            let parent_root = content_store
                .get(&parent_hash)
                .and_then(|e| decode_revision_entry(&e))
                .map(|e| e.root);
            if let Some(root) = parent_root {
                let parent_bindings = trie::collect_all_bindings(content_store, root, "");
                crate::augment_bindings_with_markers(bindings, &parent_bindings, content_store)
            } else {
                bindings
            }
        } else {
            bindings
        };

        // Build trie from bindings (replaces flat snapshot)
        let root_hash = trie::build_trie(content_store, &bindings)?;

        // §6.2 dedup (MUST per M4): if the current head already records this root,
        // return it without creating a redundant entry.
        if let Some(head_hash) = current_head {
            if let Some(head_entry) = content_store
                .get(&head_hash)
                .and_then(|e| decode_revision_entry(&e))
            {
                if head_entry.root == root_hash {
                    // `parent` field of CommitResult = the parent of the
                    // returned version entry. In the dedup path we're
                    // returning the existing HEAD, so its parent is the
                    // first entry in its `parents` list (or None).
                    let parent = head_entry.parents.first().copied();
                    return Ok((head_hash, root_hash, parent));
                }
            }
        }

        let mut parents = match current_head {
            Some(h) => vec![h],
            None => vec![],
        };
        trie::sorted_parents(&mut parents);

        let entry_data = RevisionEntryData {
            root: root_hash,
            parents,
        };
        let version_entity = build_revision_entry(&entry_data)?;
        let version_hash = content_store
            .put(version_entity)
            .map_err(|e| e.to_string())?;

        // Update head
        location_index.set(&head_path, version_hash);

        // Update active branch pointer if one exists
        let ab_path = crate::rev_active_branch_path(local_peer_id, &ph);
        if let Some(ab_hash) = location_index.get(&ab_path) {
            if let Some(ab_entity) = content_store.get(&ab_hash) {
                if let Ok(val) = ciborium::from_reader::<ciborium::Value, _>(ab_entity.data.as_slice()) {
                    if let Some(map) = val.as_map() {
                        for (k, v) in map {
                            if k.as_text() == Some("name") {
                                if let Some(branch_name) = v.as_text() {
                                    let branch_path =
                                        crate::rev_branch_path(local_peer_id, &ph, branch_name);
                                    location_index.set(&branch_path, version_hash);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((version_hash, root_hash, current_head))
    }
}

// ---------------------------------------------------------------------------
// Param decoders
// ---------------------------------------------------------------------------

fn decode_commit_params(data: &[u8]) -> Result<String, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;

    for (k, v) in map {
        if let Some("prefix") = k.as_text() {
            prefix = v.as_text().map(|s| s.to_string());
        }
    }

    prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))
}

/// Decoded `system/revision/fetch-params` (also used by `pull`, §4.4.8).
///
/// Per EXTENSION-REVISION §4.1 spec line 558, both `fetch` and `pull`
/// consume this type. The `remote` field is consumed by `pull` (§4.4.8)
/// to identify the peer to pull from; `fetch` itself ignores it — the
/// remote is implicit in the EXECUTE target URI for plain fetch.
struct FetchParams {
    prefix: String,
    remote_prefix: Option<String>,
    remote: Option<String>,
    since: Option<Hash>,
    depth: Option<usize>,
}

fn decode_fetch_params(data: &[u8]) -> Result<FetchParams, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut remote_prefix = None;
    let mut remote = None;
    let mut since = None;
    let mut depth = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("remote_prefix") => remote_prefix = v.as_text().map(|s| s.to_string()),
            Some("remote") => remote = v.as_text().map(|s| s.to_string()),
            Some("since") => {
                if let ciborium::Value::Bytes(b) = v {
                    since = Hash::from_bytes(b).ok();
                }
            }
            Some("depth") | Some("limit") => {
                depth = v.as_integer().map(|i| i128::from(i) as usize);
            }
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    Ok(FetchParams { prefix, remote_prefix, remote, since, depth })
}

fn decode_log_params(
    data: &[u8],
) -> Result<(String, Option<usize>, Option<Hash>), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut limit = None;
    let mut since = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("limit") | Some("depth") => {
                limit = v.as_integer().map(|i| i128::from(i) as usize);
            }
            Some("since") => {
                if let ciborium::Value::Bytes(b) = v {
                    since = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    Ok((prefix, limit, since))
}

fn decode_prefix_only(data: &[u8]) -> Result<String, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    for (k, v) in map {
        if k.as_text() == Some("prefix") {
            if let Some(s) = v.as_text() {
                return Ok(s.to_string());
            }
        }
    }
    Err(HandlerError::InvalidParams("missing 'prefix'".into()))
}

fn decode_ancestor_params(data: &[u8]) -> Result<(Hash, Hash), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut a = None;
    let mut b = None;

    for (k, v) in map {
        match k.as_text() {
            Some("version_a") => {
                if let ciborium::Value::Bytes(bytes) = v {
                    a = Hash::from_bytes(bytes).ok();
                }
            }
            Some("version_b") => {
                if let ciborium::Value::Bytes(bytes) = v {
                    b = Hash::from_bytes(bytes).ok();
                }
            }
            _ => {}
        }
    }

    let a = a.ok_or_else(|| HandlerError::InvalidParams("missing 'version_a'".into()))?;
    let b = b.ok_or_else(|| HandlerError::InvalidParams("missing 'version_b'".into()))?;
    Ok((a, b))
}

fn decode_branch_params(
    data: &[u8],
) -> Result<(String, String, Option<String>, Option<Hash>), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut action = None;
    let mut name = None;
    let mut from = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("action") => action = v.as_text().map(|s| s.to_string()),
            Some("name") => name = v.as_text().map(|s| s.to_string()),
            Some("from") => {
                if let ciborium::Value::Bytes(b) = v {
                    from = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    let action =
        action.ok_or_else(|| HandlerError::InvalidParams("missing 'action'".into()))?;
    Ok((prefix, action, name, from))
}

fn decode_tag_params(
    data: &[u8],
) -> Result<(String, String, Option<String>, Option<Hash>), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut action = None;
    let mut name = None;
    let mut version = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("action") => action = v.as_text().map(|s| s.to_string()),
            Some("name") => name = v.as_text().map(|s| s.to_string()),
            Some("version") => {
                if let ciborium::Value::Bytes(b) = v {
                    version = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    let action =
        action.ok_or_else(|| HandlerError::InvalidParams("missing 'action'".into()))?;
    Ok((prefix, action, name, version))
}

fn decode_checkout_params(
    data: &[u8],
) -> Result<(String, Option<String>, Option<Hash>), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut branch = None;
    let mut version = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("branch") => branch = v.as_text().map(|s| s.to_string()),
            Some("version") => {
                if let ciborium::Value::Bytes(b) = v {
                    version = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    Ok((prefix, branch, version))
}

/// Decoded merge parameters.
struct MergeParams {
    prefix: String,
    remote_version: Hash,
    strategy: Option<String>,
    dry_run: bool,
    merge_order: Option<String>,
}

fn decode_merge_params(data: &[u8]) -> Result<MergeParams, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut remote_version = None;
    let mut strategy = None;
    let mut dry_run = false;
    let mut merge_order = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("remote_version") => {
                if let ciborium::Value::Bytes(b) = v {
                    remote_version = Hash::from_bytes(b).ok();
                }
            }
            Some("strategy") => strategy = v.as_text().map(|s| s.to_string()),
            Some("dry_run") => dry_run = v.as_bool().unwrap_or(false),
            Some("merge_order") => merge_order = v.as_text().map(|s| s.to_string()),
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    let remote_version = remote_version
        .ok_or_else(|| HandlerError::InvalidParams("missing 'remote_version'".into()))?;
    Ok(MergeParams {
        prefix,
        remote_version,
        strategy,
        dry_run,
        merge_order,
    })
}

fn decode_resolve_params(data: &[u8]) -> Result<(String, String, Option<Hash>), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut path = None;
    let mut resolved = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("path") => path = v.as_text().map(|s| s.to_string()),
            Some("resolved") => {
                if let ciborium::Value::Bytes(b) = v {
                    resolved = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    let path = path.ok_or_else(|| HandlerError::InvalidParams("missing 'path'".into()))?;
    Ok((prefix, path, resolved))
}

fn decode_diff_params(data: &[u8]) -> Result<(String, Hash, Hash), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut base = None;
    let mut target = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("base") => {
                if let ciborium::Value::Bytes(b) = v {
                    base = Hash::from_bytes(b).ok();
                }
            }
            Some("target") => {
                if let ciborium::Value::Bytes(b) = v {
                    target = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    let base = base.ok_or_else(|| HandlerError::InvalidParams("missing 'base'".into()))?;
    let target =
        target.ok_or_else(|| HandlerError::InvalidParams("missing 'target'".into()))?;
    Ok((prefix, base, target))
}

/// Decoded params for cherry-pick and revert: {prefix, version, parent?}
struct VersionOpParams {
    prefix: String,
    version: Hash,
    parent: Option<Hash>,
}

/// Decode params for cherry-pick and revert: {prefix, version, parent?}
fn decode_version_op_params(data: &[u8]) -> Result<VersionOpParams, HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut version = None;
    let mut parent = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("version") => {
                if let ciborium::Value::Bytes(b) = v {
                    version = Hash::from_bytes(b).ok();
                }
            }
            Some("parent") => {
                if let ciborium::Value::Bytes(b) = v {
                    parent = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    let version =
        version.ok_or_else(|| HandlerError::InvalidParams("missing 'version'".into()))?;
    Ok(VersionOpParams { prefix, version, parent })
}

/// Decode params for push: {prefix, remote}
fn decode_push_params(data: &[u8]) -> Result<(String, String), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut remote = None;

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("remote") => remote = v.as_text().map(|s| s.to_string()),
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    let remote =
        remote.ok_or_else(|| HandlerError::InvalidParams("missing 'remote'".into()))?;
    Ok((prefix, remote))
}

/// Decode params for fetch-entities: {snapshot, hashes}
fn decode_fetch_entities_params(data: &[u8]) -> Result<(String, Hash, Vec<Hash>), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut prefix = None;
    let mut snapshot = None;
    let mut hashes = Vec::new();

    for (k, v) in map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("snapshot") => {
                if let ciborium::Value::Bytes(b) = v {
                    snapshot = Hash::from_bytes(b).ok();
                }
            }
            Some("hashes") => {
                if let ciborium::Value::Array(arr) = v {
                    for item in arr {
                        if let ciborium::Value::Bytes(b) = item {
                            if let Ok(h) = Hash::from_bytes(b) {
                                hashes.push(h);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let prefix =
        prefix.ok_or_else(|| HandlerError::InvalidParams("missing 'prefix'".into()))?;
    let snapshot =
        snapshot.ok_or_else(|| HandlerError::InvalidParams("missing 'snapshot'".into()))?;
    Ok((prefix, snapshot, hashes))
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

/// Build a `system/envelope` entity wrapping a domain result entity and its
/// included entities.  This replaces the old pattern of putting domain entities
/// directly in `HandlerResult.included`.
/// Encode an Entity as an inline CBOR value for embedding in a system/envelope.
///
/// Go's Entity struct uses `cbor.RawMessage` for data — the raw CBOR value is
/// written directly (NOT wrapped in a byte string). We must match: decode the
/// entity's data bytes back to a CBOR Value so it embeds as the native type
/// (typically a map), not as a byte string containing CBOR.
fn entity_to_inline(entity: &Entity) -> entity_ecf::Value {
    let data_value: entity_ecf::Value = ciborium::from_reader(entity.data.as_slice())
        .unwrap_or(entity_ecf::Value::Null);
    entity_ecf::Value::Map(vec![
        (entity_ecf::text("content_hash"), entity_ecf::Value::Bytes(entity.content_hash.to_bytes().to_vec())),
        (entity_ecf::text("data"), data_value),
        (entity_ecf::text("type"), entity_ecf::text(&entity.entity_type)),
    ])
}

fn build_envelope_result(root: Entity, included: std::collections::HashMap<Hash, Entity>) -> Entity {
    let included_entries: Vec<_> = included
        .iter()
        .map(|(hash, entity)| {
            (entity_ecf::Value::Bytes(hash.to_bytes().to_vec()), entity_to_inline(entity))
        })
        .collect();

    let mut envelope_fields = vec![(entity_ecf::text("root"), entity_to_inline(&root))];
    if !included.is_empty() {
        envelope_fields.push((
            entity_ecf::text("included"),
            entity_ecf::Value::Map(included_entries),
        ));
    }

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(envelope_fields));
    Entity::new(entity_types::TYPE_ENVELOPE, data)
        .expect("envelope entity creation should not fail")
}

fn error_result(status: u32, code: &str, message: &str) -> HandlerResult {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    // ENTITY-NATIVE-TYPE-SYSTEM canonical error type is `system/protocol/error`
    // (matches Go's `TypeError`). Cross-impl SDKs (Go's entitysdk/errors.go
    // and Python's analog) only read `{code, message}` from the result entity
    // when its type matches; mismatch falls back to status-default codes
    // (404→"not_found", etc), masking spec-pinned codes like `base_not_found`.
    let result = Entity::new(entity_types::TYPE_ERROR, data).unwrap();
    HandlerResult { status, result, included: std::collections::HashMap::new() }
}

fn merge_status_result(
    status: &str,
    version: Option<Hash>,
    conflict_paths: &[String],
    merged_count: usize,
    deleted_count: usize,
    warnings: &[CascadeWarning],
) -> HandlerResult {
    let mut fields = Vec::new();

    if let Some(warnings_val) = encode_cascade_warnings(warnings) {
        fields.push((entity_ecf::text("cascade_warnings"), warnings_val));
    }
    if !conflict_paths.is_empty() {
        fields.push((
            entity_ecf::text("conflicts"),
            entity_ecf::Value::Array(
                conflict_paths.iter().map(|p| entity_ecf::text(p)).collect(),
            ),
        ));
    }
    if deleted_count > 0 {
        fields.push((
            entity_ecf::text("deleted_count"),
            entity_ecf::integer(deleted_count as i64),
        ));
    }
    if merged_count > 0 {
        fields.push((
            entity_ecf::text("merged_count"),
            entity_ecf::integer(merged_count as i64),
        ));
    }
    fields.push((entity_ecf::text("status"), entity_ecf::text(status)));
    if let Some(h) = version {
        fields.push((
            entity_ecf::text("version"),
            entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }

    fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    let result = Entity::new("system/revision/merge-result", data).unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: std::collections::HashMap::new(),
    }
}

fn push_status_result(status: &str, versions: usize) -> HandlerResult {
    let mut fields = vec![
        (entity_ecf::text("status"), entity_ecf::text(status)),
    ];
    if versions > 0 {
        fields.push((
            entity_ecf::text("versions"),
            entity_ecf::integer(versions as i64),
        ));
    }
    fields.sort_by(|(a, _), (b, _)| ecf_key_cmp(a, b));

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    let result = Entity::new("system/revision/push-result", data).unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: std::collections::HashMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Shared free functions for tree-prefix qualification and snapshot computation
// ---------------------------------------------------------------------------

/// Qualify a bare prefix for tree data operations. Idempotent — already-qualified
/// prefixes are not double-qualified.
fn qualify_tree_prefix(prefix: &str, local_peer_id: &str) -> String {
    let pid_slash = format!("/{}/", local_peer_id);
    if prefix.starts_with(&pid_slash) {
        prefix.to_string()
    } else {
        format!("/{}/{}", local_peer_id, prefix)
    }
}

/// Compute snapshot bindings from the tree for a given prefix.
///
/// Accepts bare or qualified prefix (idempotent). Returns relative paths as keys.
/// Filters out `system/revision/*` paths.
fn snapshot_bindings_from_tree(
    location_index: &dyn LocationIndex,
    prefix: &str,
    local_peer_id: &str,
) -> BTreeMap<String, Hash> {
    let tree_prefix = qualify_tree_prefix(prefix, local_peer_id);
    let entries = location_index.list(&tree_prefix);
    let mut bindings = BTreeMap::new();
    let revision_prefix = format!("/{}/system/revision/", local_peer_id);
    for entry in entries {
        if entry.path.starts_with(&revision_prefix) {
            continue;
        }
        let relative = entry.path.strip_prefix(&tree_prefix).unwrap_or(&entry.path);
        if !relative.is_empty() {
            bindings.insert(relative.to_string(), entry.hash);
        }
    }
    bindings
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Compare ECF map keys by length-first then lexicographic (CBOR deterministic key ordering).
fn ecf_key_cmp(a: &entity_ecf::Value, b: &entity_ecf::Value) -> std::cmp::Ordering {
    let a_text = if let entity_ecf::Value::Text(s) = a {
        s.as_str()
    } else {
        ""
    };
    let b_text = if let entity_ecf::Value::Text(s) = b {
        s.as_str()
    } else {
        ""
    };
    a_text
        .len()
        .cmp(&b_text.len())
        .then_with(|| a_text.cmp(b_text))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_handler::HandlerContext;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn make_stores() -> (Arc<MemoryContentStore>, Arc<MemoryLocationIndex>) {
        (
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
        )
    }

    fn test_peer_id() -> String {
        // Real Base58 46-char peer ID (§5.4 validate_absolute_path requires
        // this shape on the first segment of every tree path).
        entity_crypto::Keypair::from_seed([42u8; 32])
            .peer_id()
            .as_str()
            .to_string()
    }

    fn test_ph(prefix: &str) -> String {
        prefix_hash(&resolve_prefix(prefix, &test_peer_id()))
    }

    fn make_handler(
        store: Arc<MemoryContentStore>,
        li: Arc<MemoryLocationIndex>,
    ) -> RevisionHandler {
        RevisionHandler::new(store, li, test_peer_id())
    }

    fn make_params(prefix: &str, extra_fields: Vec<(&str, entity_ecf::Value)>) -> Entity {
        let mut fields: Vec<_> = extra_fields
            .into_iter()
            .map(|(k, v)| (entity_ecf::text(k), v))
            .collect();
        fields.push((entity_ecf::text("prefix"), entity_ecf::text(prefix)));
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        Entity::new("system/revision/params", data).unwrap()
    }

    fn make_ctx(operation: &str, params: Entity) -> HandlerContext {
        let peer_id = test_peer_id();
        let qualified = format!("/{}/system/revision", peer_id);
        // Create a minimal EXECUTE entity for the context
        let exec_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "handler" => entity_ecf::text(&qualified),
            "operation" => entity_ecf::text(operation)
        });
        let execute = Entity::new("system/protocol/execute", exec_data).unwrap();

        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            pattern: qualified,
            suffix: String::new(),
            resource_target: None,
            author: Some(Hash::zero()),
            session_peer_id: None,
            request_id: "test-req".to_string(),
            operation: operation.to_string(),
            execute_fn: None,
            included: std::collections::HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        }
    }

    fn put_entity(store: &dyn ContentStore, li: &dyn LocationIndex, path: &str, content: &str) -> Hash {
        let data = entity_ecf::to_ecf(&entity_ecf::text(content));
        let entity = Entity::new("test/type", data).unwrap();
        let hash = store.put(entity).unwrap();
        // Peer-qualify bare paths so they land under the test peer's tree
        // and are visible to perform_commit's snapshot_bindings_from_tree.
        let full = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}/{}", test_peer_id(), path)
        };
        li.set(&full, hash);
        hash
    }

    /// If the result is a system/envelope, unwrap to get the root entity.
    /// Otherwise return the entity as-is.
    fn unwrap_envelope(entity: &Entity) -> Entity {
        if entity.entity_type == entity_types::TYPE_ENVELOPE {
            let val: ciborium::Value =
                ciborium::from_reader(entity.data.as_slice()).unwrap();
            let map = val.as_map().unwrap();
            let root = map
                .iter()
                .find(|(k, _)| k.as_text() == Some("root"))
                .unwrap()
                .1
                .as_map()
                .unwrap();
            let entity_type = root
                .iter()
                .find(|(k, _)| k.as_text() == Some("type"))
                .unwrap()
                .1
                .as_text()
                .unwrap()
                .to_string();
            let data_value = &root
                .iter()
                .find(|(k, _)| k.as_text() == Some("data"))
                .unwrap()
                .1;
            let mut buf = Vec::new();
            ciborium::into_writer(data_value, &mut buf).unwrap();
            Entity::new(&entity_type, buf).unwrap()
        } else {
            entity.clone()
        }
    }

    fn decode_result_field(entity: &Entity, field: &str) -> Option<ciborium::Value> {
        let unwrapped = unwrap_envelope(entity);
        let val: ciborium::Value = ciborium::from_reader(unwrapped.data.as_slice()).ok()?;
        let map = val.as_map()?;
        for (k, v) in map {
            if k.as_text() == Some(field) {
                return Some(v.clone());
            }
        }
        None
    }

    #[tokio::test]
    async fn test_commit_creates_version() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // Put some data in the tree
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "hello");
        put_entity(store.as_ref(), li.as_ref(), "data/bar", "world");

        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let result = handler.handle(&ctx).await.unwrap();

        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, "system/revision/commit-result");

        // Check root is present in result (EXTENSION-REVISION §4.3.1)
        let root = decode_result_field(&result.result, "root");
        assert!(root.is_some());

        // Head should now be set
        assert!(li.get(&rev_head_path(&test_peer_id(), &test_ph("data/"))).is_some());
    }

    fn make_merge_config_params(
        scope: &str,
        name: &str,
        action: &str,
        pattern: Option<&str>,
        strategy: Option<&str>,
        deletion_resolution: Option<&str>,
    ) -> Entity {
        let mut config_fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();
        if let Some(p) = pattern {
            config_fields.push((entity_ecf::text("pattern"), entity_ecf::text(p)));
        }
        if let Some(s) = strategy {
            config_fields.push((entity_ecf::text("strategy"), entity_ecf::text(s)));
        }
        if let Some(dr) = deletion_resolution {
            config_fields
                .push((entity_ecf::text("deletion_resolution"), entity_ecf::text(dr)));
        }
        let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = vec![
            (entity_ecf::text("scope"), entity_ecf::text(scope)),
            (entity_ecf::text("name"), entity_ecf::text(name)),
            (entity_ecf::text("action"), entity_ecf::text(action)),
        ];
        if action == "set" {
            fields.push((
                entity_ecf::text("config"),
                entity_ecf::Value::Map(config_fields),
            ));
        }
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        Entity::new("system/revision/merge-config-params", data).unwrap()
    }

    #[tokio::test]
    async fn merge_config_set_rejects_deletion_resolution_lww() {
        // EXTENSION-REVISION v3.1 §2.3: `deletion_resolution: lww` MUST be
        // rejected at config-write time with `invalid_strategy`.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        let params = make_merge_config_params(
            "path", "test", "set", Some("*"), Some("three-way"), Some("lww"),
        );
        let ctx = make_ctx("merge-config", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST, "lww must be rejected");
        // The error entity carries the canonical `invalid_strategy` code.
        let v: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = v.as_map().unwrap();
        let code = map
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("code") {
                    v.as_text().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        assert_eq!(code, "invalid_strategy");
        // Binding MUST NOT have landed.
        let path = format!(
            "/{}/system/revision/config/merge/path/test",
            test_peer_id()
        );
        assert!(
            li.get(&path).is_none(),
            "rejected config MUST NOT be bound at the merge-config path"
        );
    }

    #[tokio::test]
    async fn merge_config_set_rejects_deletion_resolution_keep_both() {
        // EXTENSION-REVISION v3.1 §2.3: `deletion_resolution: keep-both` MUST
        // be rejected at config-write time.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        let params = make_merge_config_params(
            "path", "test", "set", Some("*"), Some("three-way"), Some("keep-both"),
        );
        let ctx = make_ctx("merge-config", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
        let v: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = v.as_map().unwrap();
        let code = map
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("code") {
                    v.as_text().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        assert_eq!(code, "invalid_strategy");
    }

    #[tokio::test]
    async fn merge_config_set_accepts_valid_deletion_resolution() {
        // Valid values (`preserve-on-conflict`, `deletion-wins`,
        // `three-way-fallthrough`, `deterministic`) MUST be accepted.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        for dr in [
            "preserve-on-conflict",
            "deletion-wins",
            "three-way-fallthrough",
            "deterministic",
        ] {
            let params = make_merge_config_params(
                "path", "test", "set", Some("*"), Some("three-way"), Some(dr),
            );
            let ctx = make_ctx("merge-config", params);
            let result = handler.handle(&ctx).await.unwrap();
            assert_eq!(
                result.status, STATUS_OK,
                "deletion_resolution={:?} MUST be accepted",
                dr
            );
        }
        // Binding is present at the canonical path.
        let path = format!(
            "/{}/system/revision/config/merge/path/test",
            test_peer_id()
        );
        assert!(li.get(&path).is_some());
    }

    #[tokio::test]
    async fn commit_emits_deletion_marker_for_unbound_paths() {
        // EXTENSION-REVISION v3.1 §6.1: every path bound in the parent
        // version's trie MUST appear in the new version's trie — either
        // as a live binding or as the canonical deletion marker. The
        // marker entity is the canonical zero-field
        // `system/deletion-marker` (NATIVE-TYPE-SYSTEM §4.9).
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // Commit v1 with two paths bound.
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v1-foo");
        put_entity(store.as_ref(), li.as_ref(), "data/bar", "v1-bar");
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        handler.handle(&ctx).await.unwrap();
        let v1_head = li
            .get(&rev_head_path(&test_peer_id(), &test_ph("data/")))
            .expect("v1 head bound");

        // Unbind foo in the live tree. Commit v2.
        li.remove(&format!("/{}/data/foo", test_peer_id()));
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        handler.handle(&ctx).await.unwrap();
        let v2_head = li
            .get(&rev_head_path(&test_peer_id(), &test_ph("data/")))
            .expect("v2 head bound");
        assert_ne!(v1_head, v2_head, "v2 must be a distinct version");

        // The v2 trie MUST bind the unbound path to the canonical
        // deletion marker hash (relative paths; the trie is built from
        // bindings stripped of the prefix).
        let v2_bindings = handler.get_version_bindings(v2_head).expect("v2 bindings");
        let marker = entity_entity::canonical_deletion_marker_hash();
        assert_eq!(
            v2_bindings.get("foo").copied(),
            Some(marker),
            "v2 trie MUST carry the deletion marker at the unbound path",
        );
        // `bar` still bound — must have its real entity hash, not a marker.
        let bar_hash = v2_bindings.get("bar").copied().expect("bar bound");
        assert_ne!(bar_hash, marker, "still-bound path must not carry a marker");
    }

    #[tokio::test]
    async fn test_commit_log_roundtrip() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v1");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v2");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        // Log should show 2 versions
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("log", params);
        let result = handler.handle(&ctx).await.unwrap();

        assert_eq!(result.status, STATUS_OK);
        let versions = decode_result_field(&result.result, "versions").unwrap();
        if let ciborium::Value::Array(arr) = versions {
            assert_eq!(arr.len(), 2);
        } else {
            panic!("versions should be array");
        }
    }

    #[tokio::test]
    async fn test_status_no_versions() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        let params = make_params("data/", vec![]);
        let ctx = make_ctx("status", params);
        let result = handler.handle(&ctx).await.unwrap();

        assert_eq!(result.status, STATUS_OK);
        let conflicts = decode_result_field(&result.result, "conflicts").unwrap();
        assert_eq!(i128::from(conflicts.as_integer().unwrap()), 0);
    }

    #[tokio::test]
    async fn test_find_ancestor() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // Create two commits
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v1");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let r1 = handler.handle(&ctx).await.unwrap();
        let v1_bytes = decode_result_field(&r1.result, "version").unwrap();
        let v1 = if let ciborium::Value::Bytes(b) = v1_bytes {
            Hash::from_bytes(&b).unwrap()
        } else {
            panic!("expected bytes")
        };

        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v2");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let r2 = handler.handle(&ctx).await.unwrap();
        let v2_bytes = decode_result_field(&r2.result, "version").unwrap();
        let v2 = if let ciborium::Value::Bytes(b) = v2_bytes {
            Hash::from_bytes(&b).unwrap()
        } else {
            panic!("expected bytes")
        };

        // Find ancestor should return v1
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("version_a"),
                entity_ecf::Value::Bytes(v1.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("version_b"),
                entity_ecf::Value::Bytes(v2.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/ancestor-params", params_data).unwrap();
        let ctx = make_ctx("find-ancestor", params);
        let result = handler.handle(&ctx).await.unwrap();

        assert_eq!(result.status, STATUS_OK);
        let ancestor = decode_result_field(&result.result, "ancestor");
        assert!(ancestor.is_some());
    }

    #[tokio::test]
    async fn test_branch_create_list_delete() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // Create a commit first
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "content");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        // Create branch
        let params = make_params("data/", vec![
            ("action", entity_ecf::text("create")),
            ("name", entity_ecf::text("feature")),
        ]);
        let ctx = make_ctx("branch", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        // List branches
        let params = make_params("data/", vec![
            ("action", entity_ecf::text("list")),
        ]);
        let ctx = make_ctx("branch", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let branches = decode_result_field(&result.result, "branches").unwrap();
        if let ciborium::Value::Map(m) = branches {
            assert!(!m.is_empty());
        }

        // Delete branch
        let params = make_params("data/", vec![
            ("action", entity_ecf::text("delete")),
            ("name", entity_ecf::text("feature")),
        ]);
        let ctx = make_ctx("branch", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
    }

    #[tokio::test]
    async fn test_tag_immutability() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        put_entity(store.as_ref(), li.as_ref(), "data/foo", "content");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        // Create tag
        let params = make_params("data/", vec![
            ("action", entity_ecf::text("create")),
            ("name", entity_ecf::text("v1.0")),
        ]);
        let ctx = make_ctx("tag", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        // Try to create same tag again — should fail with 409
        let params = make_params("data/", vec![
            ("action", entity_ecf::text("create")),
            ("name", entity_ecf::text("v1.0")),
        ]);
        let ctx = make_ctx("tag", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
    }

    #[tokio::test]
    async fn test_checkout_branch() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // Setup: commit v1, create branch, commit v2 on main
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v1");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        // Create a branch at current head
        let params = make_params("data/", vec![
            ("action", entity_ecf::text("create")),
            ("name", entity_ecf::text("feature")),
        ]);
        let ctx = make_ctx("branch", params);
        handler.handle(&ctx).await.unwrap();

        // Modify and commit again
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v2");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        // Checkout the feature branch (should revert data/foo to v1)
        let params = make_params("data/", vec![
            ("branch", entity_ecf::text("feature")),
        ]);
        let ctx = make_ctx("checkout", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
    }

    // -----------------------------------------------------------------------
    // Pull (§4.4.8) — basic precondition checks. End-to-end behavior requires
    // a wire-connected remote peer and is exercised by the cross-impl probe.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_pull_missing_remote_returns_400() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        // Pull with only a prefix, no remote — MUST reject 400 invalid_params.
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("pull", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let code = val
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .unwrap()
            .1
            .as_text()
            .unwrap()
            .to_string();
        assert_eq!(code, "invalid_params");
    }

    #[tokio::test]
    async fn test_pull_no_execute_fn_returns_500() {
        // The test ctx has execute_fn=None. With remote set, pull MUST
        // surface this as 500 internal_error (handler context missing
        // execute_fn). Production wiring always provides one.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        let params = make_params(
            "data/",
            vec![("remote", entity_ecf::text("bogus-peer-id"))],
        );
        let ctx = make_ctx("pull", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_INTERNAL_ERROR);
        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let code = val
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .unwrap()
            .1
            .as_text()
            .unwrap()
            .to_string();
        assert_eq!(code, "internal_error");
    }

    #[tokio::test]
    async fn test_pull_advertised_in_operations() {
        // Regression guard for the spec dispatch advertisement —
        // CLAUDE.md "implement the spec literally" and EXTENSION-REVISION
        // §4.4.8 require `pull` to be a recognized operation.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        assert!(handler.operations().contains(&"pull"));
    }

    #[tokio::test]
    async fn test_diff_between_versions() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // Commit v1
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v1");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let r1 = handler.handle(&ctx).await.unwrap();
        let v1 = extract_version_hash(&r1.result);

        // Commit v2
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v2");
        put_entity(store.as_ref(), li.as_ref(), "data/bar", "new");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let r2 = handler.handle(&ctx).await.unwrap();
        let v2 = extract_version_hash(&r2.result);

        // Diff
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(v1.to_bytes().to_vec()),
            ),
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(v2.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/diff-params", params_data).unwrap();
        let ctx = make_ctx("diff", params);
        let result = handler.handle(&ctx).await.unwrap();

        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, "system/tree/diff");
    }

    #[tokio::test]
    async fn test_cherry_pick() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // v1: base
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "base");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        // v2: add bar
        put_entity(store.as_ref(), li.as_ref(), "data/bar", "bar_content");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let r2 = handler.handle(&ctx).await.unwrap();
        let v2 = extract_version_hash(&r2.result);

        // v3: change foo (forget bar for now, but it's still there)
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "modified");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        // Cherry-pick v2 (should be a no-op merge since bar is already there)
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(v2.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/cherry-pick-params", params_data).unwrap();
        let ctx = make_ctx("cherry-pick", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
    }

    #[tokio::test]
    async fn test_revert() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // v1: foo=original
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "original");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        // v2: foo=changed
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "changed");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let r2 = handler.handle(&ctx).await.unwrap();
        let v2 = extract_version_hash(&r2.result);

        // Revert v2
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(v2.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/revert-params", params_data).unwrap();
        let ctx = make_ctx("revert", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
    }

    #[tokio::test]
    async fn revert_unbinds_file_added_by_target_version() {
        // EXTENSION-REVISION v3.1 §4.4.4 Amendment 3 — version-
        // transcription apply MUST translate marker bindings to
        // live-tree unbinds. The validator vector `revert_file_removed`
        // commits v2 that adds a path, reverts v2, asserts the path is
        // unbound. Under v3.1 absence-is-preserve, the bug was that
        // V_target (parent) had no opinion on the path V_revert added,
        // so the merge preserved local's binding instead of unbinding.
        // Fix: `augment_bindings_with_markers` injects the canonical
        // marker into the remote view at V_revert-added paths.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // v1: only `foo`.
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v1-foo");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        handler.handle(&ctx).await.unwrap();

        // v2: adds `bar`.
        put_entity(store.as_ref(), li.as_ref(), "data/bar", "v2-bar-added");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let r2 = handler.handle(&ctx).await.unwrap();
        let v2 = extract_version_hash(&r2.result);

        // Live tree pre-revert MUST have `bar` bound.
        let bar_path = format!("/{}/data/bar", test_peer_id());
        assert!(
            li.get(&bar_path).is_some(),
            "data/bar must be bound after v2 commit"
        );

        // Revert v2 — `bar` should disappear from the live tree.
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(v2.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/revert-params", params_data).unwrap();
        let ctx = make_ctx("revert", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        assert!(
            li.get(&bar_path).is_none(),
            "v3.1 Amendment 3: revert MUST unbind data/bar from the live tree"
        );
        // `foo` remains.
        let foo_path = format!("/{}/data/foo", test_peer_id());
        assert!(li.get(&foo_path).is_some(), "data/foo must remain bound");
    }

    #[tokio::test]
    async fn test_merge_fast_forward() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        // v1
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v1");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let r1 = handler.handle(&ctx).await.unwrap();
        let v1 = extract_version_hash(&r1.result);

        // v2 (child of v1)
        put_entity(store.as_ref(), li.as_ref(), "data/foo", "v2");
        let params = make_params("data/", vec![]);
        let ctx = make_ctx("commit", params);
        let r2 = handler.handle(&ctx).await.unwrap();
        let v2 = extract_version_hash(&r2.result);

        // Roll head back to v1
        li.set(&rev_head_path(&test_peer_id(), &test_ph("data/")), v1);

        // Merge v2 should fast-forward
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("remote_version"),
                entity_ecf::Value::Bytes(v2.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/merge-params", params_data).unwrap();
        let ctx = make_ctx("merge", params);
        let result = handler.handle(&ctx).await.unwrap();

        assert_eq!(result.status, STATUS_OK);
        let status_val = decode_result_field(&result.result, "status").unwrap();
        assert_eq!(status_val.as_text().unwrap(), "fast_forward");
    }

    #[tokio::test]
    async fn test_resolve_conflict() {
        let (store, li) = make_stores();

        // Manually create a conflict entry
        let conflict_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "path" => entity_ecf::text("foo"),
            "strategy" => entity_ecf::text("three-way")
        });
        let conflict_entity = Entity::new("system/revision/conflict", conflict_data).unwrap();
        let conflict_hash = store.put(conflict_entity).unwrap();
        li.set(&rev_conflict_path(&test_peer_id(), &test_ph("data/"), "foo"), conflict_hash);

        // Put a resolved entity
        let resolved_data = entity_ecf::to_ecf(&entity_ecf::text("resolved"));
        let resolved_entity = Entity::new("test/type", resolved_data).unwrap();
        let resolved_hash = store.put(resolved_entity).unwrap();

        let handler = make_handler(store.clone(), li.clone());

        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("path"), entity_ecf::text("foo")),
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("resolved"),
                entity_ecf::Value::Bytes(resolved_hash.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/resolve-params", params_data).unwrap();
        let ctx = make_ctx("resolve", params);
        let result = handler.handle(&ctx).await.unwrap();

        assert_eq!(result.status, STATUS_OK);
        // Conflict should be removed
        assert!(li.get(&rev_conflict_path(&test_peer_id(), &test_ph("data/"), "foo")).is_none());
        // Resolved entity should be at the qualified tree path
        assert_eq!(li.get(&format!("/{}/data/foo", test_peer_id())), Some(resolved_hash));
    }

    fn extract_version_hash(result: &Entity) -> Hash {
        // All revision results carry the version under `version` per
        // EXTENSION-REVISION §4.3.x (commit, merge, cherry-pick, revert).
        let v_bytes = decode_result_field(result, "version").unwrap();
        if let ciborium::Value::Bytes(b) = v_bytes {
            Hash::from_bytes(&b).unwrap()
        } else {
            panic!("expected bytes for version hash")
        }
    }

    /// Reproduce Go validator issue #10: checkout doesn't remove files from prior version.
    /// Uses peer-qualified storage paths + bare prefix in params (matching production).
    #[tokio::test]
    async fn test_checkout_removes_files() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        let pid = test_peer_id();

        // v1: file1, file2 (stored at qualified paths, bare prefix in params)
        put_entity(store.as_ref(), li.as_ref(), &format!("/{}/data/file1", pid), "content1");
        put_entity(store.as_ref(), li.as_ref(), &format!("/{}/data/file2", pid), "content2");
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        let r1 = handler.handle(&ctx).await.unwrap();
        let v1 = extract_version_hash(&r1.result);

        // v2: file1, file2, file3
        put_entity(store.as_ref(), li.as_ref(), &format!("/{}/data/file3", pid), "content3");
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        handler.handle(&ctx).await.unwrap();

        // Checkout to v1
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(v1.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/checkout-params", params_data).unwrap();
        let ctx = make_ctx("checkout", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        // file3 should be removed (check qualified path)
        assert!(
            li.get(&format!("/{}/data/file3", pid)).is_none(),
            "file3 should not exist after checkout to v1"
        );
        // file1, file2 should still exist
        assert!(li.get(&format!("/{}/data/file1", pid)).is_some(), "file1 should still exist");
        assert!(li.get(&format!("/{}/data/file2", pid)).is_some(), "file2 should still exist");
    }

    /// Same as above but with already-qualified prefix in params (idempotent qualification).
    #[tokio::test]
    async fn test_checkout_removes_files_qualified() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        let pid = test_peer_id();
        let qualified_prefix = format!("/{}/data/", pid);

        // v1: file1, file2 (at qualified paths, qualified prefix in params)
        put_entity(store.as_ref(), li.as_ref(), &format!("{}file1", qualified_prefix), "content1");
        put_entity(store.as_ref(), li.as_ref(), &format!("{}file2", qualified_prefix), "content2");
        let ctx = make_ctx("commit", make_params(&qualified_prefix, vec![]));
        let r1 = handler.handle(&ctx).await.unwrap();
        let v1 = extract_version_hash(&r1.result);

        // v2: add file3
        put_entity(store.as_ref(), li.as_ref(), &format!("{}file3", qualified_prefix), "content3");
        let ctx = make_ctx("commit", make_params(&qualified_prefix, vec![]));
        handler.handle(&ctx).await.unwrap();

        // Checkout to v1 (qualified prefix in params — tests idempotent qualification)
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text(&qualified_prefix)),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(v1.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/checkout-params", params_data).unwrap();
        let ctx = make_ctx("checkout", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        // file3 should be removed
        assert!(
            li.get(&format!("{}file3", qualified_prefix)).is_none(),
            "file3 should not exist after checkout to v1"
        );
        assert!(li.get(&format!("{}file1", qualified_prefix)).is_some(), "file1 should still exist");
        assert!(li.get(&format!("{}file2", qualified_prefix)).is_some(), "file2 should still exist");
    }

    // -------------------------------------------------------------------
    // Stage 4: head-advance ordering + active-branch advance on merge
    // (PROPOSAL-REVISION-AUTO-VERSION-FIX §6A)
    // -------------------------------------------------------------------

    /// Spy LocationIndex that records the order of set() calls so tests can
    /// assert head and branch writes precede tracked-prefix bindings.
    struct OrderingSpy {
        inner: Arc<MemoryLocationIndex>,
        log: std::sync::Mutex<Vec<String>>,
    }

    impl OrderingSpy {
        fn new(inner: Arc<MemoryLocationIndex>) -> Arc<Self> {
            Arc::new(Self { inner, log: std::sync::Mutex::new(Vec::new()) })
        }
        fn log(&self) -> Vec<String> { self.log.lock().unwrap().clone() }
    }

    impl entity_store::LocationIndex for OrderingSpy {
        fn set(&self, path: &str, hash: Hash) {
            self.log.lock().unwrap().push(format!("set {}", path));
            self.inner.set(path, hash);
        }
        fn get(&self, path: &str) -> Option<Hash> { self.inner.get(path) }
        fn has(&self, path: &str) -> bool { self.inner.has(path) }
        fn remove(&self, path: &str) -> Option<Hash> {
            self.log.lock().unwrap().push(format!("remove {}", path));
            self.inner.remove(path)
        }
        fn list(&self, prefix: &str) -> Vec<entity_store::LocationEntry> {
            self.inner.list(prefix)
        }
        fn len_prefix(&self, prefix: &str) -> usize {
            self.inner.len_prefix(prefix)
        }
    }

    fn position(log: &[String], needle: &str) -> Option<usize> {
        log.iter().position(|s| s.contains(needle))
    }

    /// Merge's diverged path must advance head and active-branch before
    /// applying merged bindings (§6A.1). This is also the fix for the
    /// pre-existing bug where merge didn't advance the active branch.
    #[tokio::test]
    async fn merge_diverged_advances_head_and_branch_before_bindings() {
        let (store, inner_li) = make_stores();
        let spy = OrderingSpy::new(inner_li.clone());
        let li: Arc<dyn entity_store::LocationIndex> = spy.clone();
        let handler = Arc::new(RevisionHandler::new(
            store.clone(),
            li.clone(),
            test_peer_id(),
        ));

        let peer = test_peer_id();
        let qp = |p: &str| format!("/{}/{}", peer, p);

        // Base version on a branch; both peers will diverge from it.
        put_entity(store.as_ref(), inner_li.as_ref(), &qp("data/base"), "v0");
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        let base = handler.handle(&ctx).await.unwrap();
        let base_v = extract_version_hash(&base.result);

        // Create a branch "main" pointing at base + mark as active.
        let tph = test_ph("data/");
        inner_li.set(
            &rev_branch_path(&peer, &tph, "main"),
            base_v,
        );
        // Set active branch to main.
        let ab_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("name"),
            entity_ecf::text("main"),
        )]));
        let ab_entity = Entity::new("system/revision/active-branch", ab_data).unwrap();
        let ab_hash = store.put(ab_entity).unwrap();
        inner_li.set(
            &rev_active_branch_path(&peer, &tph),
            ab_hash,
        );

        // Local diverges: modify base.
        put_entity(store.as_ref(), inner_li.as_ref(), &qp("data/base"), "local");
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        let local = handler.handle(&ctx).await.unwrap();

        // Build a remote divergent version: roll head back, write different data, commit, then push head forward.
        inner_li.set(&rev_head_path(&peer, &tph), base_v);
        put_entity(store.as_ref(), inner_li.as_ref(), &qp("data/base"), "remote");
        put_entity(store.as_ref(), inner_li.as_ref(), &qp("data/extra"), "remote_only");
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        let remote = handler.handle(&ctx).await.unwrap();
        let remote_v = extract_version_hash(&remote.result);

        // Restore head to local to set up the diverged state.
        let local_v = extract_version_hash(&local.result);
        inner_li.set(
            &rev_head_path(&peer, &tph),
            local_v,
        );
        // Clear the spy log — we only want the merge's writes.
        spy.log.lock().unwrap().clear();

        // Merge remote into local.
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("remote_version"),
                entity_ecf::Value::Bytes(remote_v.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/merge-params", params_data).unwrap();
        let ctx = make_ctx("merge", params);
        let _ = handler.handle(&ctx).await.unwrap();

        let log = spy.log();
        let head_pos = position(&log, "/head")
            .expect("head should be advanced");
        let branch_pos = position(&log, "/branches/main")
            .expect("active branch should be advanced — regression test");
        let data_pos = log
            .iter()
            .position(|s| s.contains("/data/") && !s.contains("system/"))
            .expect("data binding should land");
        assert!(
            head_pos < data_pos,
            "head must advance before bindings; log = {:?}",
            log
        );
        assert!(
            branch_pos < data_pos,
            "active branch must advance before bindings; log = {:?}",
            log
        );
    }

    #[tokio::test]
    async fn cherry_pick_advances_head_before_bindings() {
        let (store, inner_li) = make_stores();
        let spy = OrderingSpy::new(inner_li.clone());
        let li: Arc<dyn entity_store::LocationIndex> = spy.clone();
        let handler =
            Arc::new(RevisionHandler::new(store.clone(), li.clone(), test_peer_id()));

        // v1 base, v2 adds bar, v3 modifies foo.
        put_entity(store.as_ref(), inner_li.as_ref(), "data/foo", "base");
        handler.handle(&make_ctx("commit", make_params("data/", vec![]))).await.unwrap();

        put_entity(store.as_ref(), inner_li.as_ref(), "data/bar", "bar");
        let r2 = handler
            .handle(&make_ctx("commit", make_params("data/", vec![])))
            .await
            .unwrap();
        let v2 = extract_version_hash(&r2.result);

        put_entity(store.as_ref(), inner_li.as_ref(), "data/foo", "modified");
        handler.handle(&make_ctx("commit", make_params("data/", vec![]))).await.unwrap();

        spy.log.lock().unwrap().clear();
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(v2.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/cherry-pick-params", params_data).unwrap();
        let _ = handler.handle(&make_ctx("cherry-pick", params)).await.unwrap();

        let log = spy.log();
        let head_pos = position(&log, "/head").unwrap_or(usize::MAX);
        let data_writes: Vec<usize> = log
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                if s.contains("/data/") && !s.contains("system/") {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();
        if let Some(first_data) = data_writes.first() {
            assert!(
                head_pos < *first_data,
                "head must precede data writes; log = {:?}",
                log
            );
        }
    }

    #[tokio::test]
    async fn checkout_advances_head_before_bindings() {
        let (store, inner_li) = make_stores();
        let spy = OrderingSpy::new(inner_li.clone());
        let li: Arc<dyn entity_store::LocationIndex> = spy.clone();
        let handler =
            Arc::new(RevisionHandler::new(store.clone(), li.clone(), test_peer_id()));

        put_entity(store.as_ref(), inner_li.as_ref(), "data/file1", "v1");
        let r1 = handler
            .handle(&make_ctx("commit", make_params("data/", vec![])))
            .await
            .unwrap();
        let v1 = extract_version_hash(&r1.result);

        put_entity(store.as_ref(), inner_li.as_ref(), "data/file2", "v2");
        handler.handle(&make_ctx("commit", make_params("data/", vec![]))).await.unwrap();

        spy.log.lock().unwrap().clear();
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(v1.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/checkout-params", params_data).unwrap();
        let _ = handler.handle(&make_ctx("checkout", params)).await.unwrap();

        let log = spy.log();
        let head_pos = position(&log, "/head").unwrap_or(usize::MAX);
        if let Some(first_data) = log.iter().position(|s| s.contains("/data/") && !s.contains("system/")) {
            assert!(
                head_pos < first_data,
                "head must precede data writes; log = {:?}",
                log
            );
        }
    }

    /// §6.2 SHOULD — `revision/commit` with no tree changes returns the
    /// current head instead of creating a redundant entry whose root matches.
    #[tokio::test]
    async fn commit_dedup_returns_current_head_when_root_unchanged() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        put_entity(store.as_ref(), li.as_ref(), "data/file", "v1");
        let r1 = handler
            .handle(&make_ctx("commit", make_params("data/", vec![])))
            .await
            .unwrap();
        let v1 = extract_version_hash(&r1.result);

        // Second commit with no changes — must dedup to v1.
        let r2 = handler
            .handle(&make_ctx("commit", make_params("data/", vec![])))
            .await
            .unwrap();
        let v2 = extract_version_hash(&r2.result);
        assert_eq!(v1, v2, "second commit must return current head, not a new entry");

        // Log should show exactly one version.
        let log_result = handler
            .handle(&make_ctx("log", make_params("data/", vec![])))
            .await
            .unwrap();
        let versions = decode_result_field(&log_result.result, "versions").unwrap();
        if let ciborium::Value::Array(arr) = versions {
            assert_eq!(arr.len(), 1, "no redundant entry should be created");
        } else {
            panic!("versions not an array");
        }
    }

    /// Checkout under auto_version:true with policy "deny" must reject.
    #[tokio::test]
    async fn checkout_denied_under_auto_version_deny_policy() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        let peer = test_peer_id();

        // Commit a version first so a target exists.
        put_entity(store.as_ref(), li.as_ref(), "data/f", "v1");
        let r1 = handler
            .handle(&make_ctx("commit", make_params("data/", vec![])))
            .await
            .unwrap();
        let v1 = extract_version_hash(&r1.result);

        // Install a config with auto_version:true + policy deny.
        let cfg_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("auto_version"), entity_ecf::bool_val(true)),
            (
                entity_ecf::text("checkout_under_auto_version"),
                entity_ecf::text("deny"),
            ),
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
        ]));
        let cfg_entity = Entity::new("system/revision/config", cfg_data).unwrap();
        let cfg_hash = store.put(cfg_entity).unwrap();
        li.set(
            &rev_config_path(&peer, &test_ph("data/")),
            cfg_hash,
        );

        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("version"),
                entity_ecf::Value::Bytes(v1.to_bytes().to_vec()),
            ),
        ]));
        let params = Entity::new("system/revision/checkout-params", params_data).unwrap();
        let result = handler.handle(&make_ctx("checkout", params)).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    /// R4: handler-level keep-both merge — mirrors Go validator checks
    /// keep_both_strategy_applied, keep_both_additional_binding, keep_both_original_entity
    #[tokio::test]
    async fn test_merge_keep_both_handler() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());
        let pid = test_peer_id();
        let qp = |p: &str| format!("/{}/{}", pid, p);

        // v1: base state
        put_entity(store.as_ref(), li.as_ref(), &qp("data/shared"), "base");
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        let r = handler.handle(&ctx).await.unwrap();
        let v1 = extract_version_hash(&r.result);

        // v2: local edits shared
        put_entity(store.as_ref(), li.as_ref(), &qp("data/shared"), "local_edit");
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        let r = handler.handle(&ctx).await.unwrap();
        let v2_local = extract_version_hash(&r.result);

        // Roll head back to v1, create divergent remote version
        li.set(&rev_head_path(&pid, &test_ph("data/")), v1);
        put_entity(store.as_ref(), li.as_ref(), &qp("data/shared"), "remote_edit");
        let ctx = make_ctx("commit", make_params("data/", vec![]));
        let r = handler.handle(&ctx).await.unwrap();
        let v2_remote = extract_version_hash(&r.result);

        // Restore head to local
        li.set(&rev_head_path(&pid, &test_ph("data/")), v2_local);

        // Merge with strategy=keep-both
        let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("prefix"), entity_ecf::text("data/")),
            (
                entity_ecf::text("remote_version"),
                entity_ecf::Value::Bytes(v2_remote.to_bytes().to_vec()),
            ),
            (entity_ecf::text("strategy"), entity_ecf::text("keep-both")),
        ]));
        let params = Entity::new("system/revision/merge-params", params_data).unwrap();
        let ctx = make_ctx("merge", params);
        let result = handler.handle(&ctx).await.unwrap();

        assert_eq!(result.status, STATUS_OK);

        // keep_both_strategy_applied: status must be "merged" (no conflicts)
        let status = decode_result_field(&result.result, "status").unwrap();
        assert_eq!(
            status.as_text().unwrap(), "merged",
            "keep-both should resolve edit-vs-edit without conflicts"
        );

        // keep_both_original_entity: one side's entity at original path
        let original_binding = li.get(&qp("data/shared"));
        assert!(original_binding.is_some(), "original path should have a binding");

        // keep_both_additional_binding: other side at .keep-both-{hex} path
        let tree_entries = li.list(&qp("data/"));
        let keep_both_entries: Vec<_> = tree_entries
            .iter()
            .filter(|e| e.path.contains(".keep-both-"))
            .collect();
        assert_eq!(
            keep_both_entries.len(), 1,
            "should have exactly 1 keep-both binding, got: {:?}",
            keep_both_entries.iter().map(|e| &e.path).collect::<Vec<_>>()
        );
        let kb_path = &keep_both_entries[0].path;
        assert!(
            kb_path.contains("data/shared.keep-both-"),
            "keep-both path should be based on original: {}",
            kb_path
        );
        // Hash suffix should be 8 hex chars
        let suffix = kb_path.split(".keep-both-").nth(1).unwrap();
        assert_eq!(suffix.len(), 8, "hash prefix suffix should be 8 hex chars");
    }

    // -----------------------------------------------------------------------
    // EXTENSION-REVISION v3.4 §4.4.19 — fetch-diff
    // -----------------------------------------------------------------------

    fn fetch_diff_params(prefix: &str, base: Option<Hash>) -> Entity {
        let mut extras: Vec<(&str, entity_ecf::Value)> = Vec::new();
        if let Some(b) = base {
            extras.push((
                "base",
                entity_ecf::Value::Bytes(b.to_bytes().to_vec()),
            ));
        }
        make_params(prefix, extras)
    }

    #[tokio::test]
    async fn test_fetch_diff_full_closure_zero_base() {
        // §4.4.19: with no `base`, return the full closure for the current
        // head — every trie node + every binding entity reachable.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        put_entity(store.as_ref(), li.as_ref(), "data/a", "alpha");
        put_entity(store.as_ref(), li.as_ref(), "data/b", "bravo");
        put_entity(store.as_ref(), li.as_ref(), "data/c", "charlie");

        let commit = handler.handle(&make_ctx("commit", make_params("data/", vec![]))).await.unwrap();
        assert_eq!(commit.status, STATUS_OK);

        let ctx = make_ctx("fetch-diff", fetch_diff_params("data/", None));
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_ENVELOPE);

        // Envelope must contain at least: trie root node + 3 leaf entities.
        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let included = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("included"))
            .map(|(_, v)| v.as_map().unwrap());
        let n = included.map(|m| m.len()).unwrap_or(0);
        assert!(n >= 3, "full closure must include trie + leaves, got {}", n);
    }

    #[tokio::test]
    async fn test_fetch_diff_incremental_bandwidth() {
        // §4.4.19: with `base` set to the head before a single change, the
        // returned closure MUST be materially smaller than the full closure.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        for i in 0..10 {
            put_entity(
                store.as_ref(),
                li.as_ref(),
                &format!("data/leaf-{:02}", i),
                &format!("v0-{}", i),
            );
        }
        // First commit becomes the base.
        let commit1 = handler.handle(&make_ctx("commit", make_params("data/", vec![]))).await.unwrap();
        assert_eq!(commit1.status, STATUS_OK);
        let base_hash = {
            let ph = test_ph("data/");
            li.get(&format!("/{}/system/revision/{}/head", test_peer_id(), ph)).unwrap()
        };

        // Change one leaf, commit again.
        put_entity(store.as_ref(), li.as_ref(), "data/leaf-05", "v1");
        let commit2 = handler.handle(&make_ctx("commit", make_params("data/", vec![]))).await.unwrap();
        assert_eq!(commit2.status, STATUS_OK);

        let full = handler.handle(&make_ctx("fetch-diff", fetch_diff_params("data/", None))).await.unwrap();
        let incr = handler.handle(&make_ctx("fetch-diff", fetch_diff_params("data/", Some(base_hash)))).await.unwrap();
        assert_eq!(full.status, STATUS_OK);
        assert_eq!(incr.status, STATUS_OK);

        let included_len = |e: &Entity| -> usize {
            let val: ciborium::Value =
                ciborium::from_reader(e.data.as_slice()).unwrap();
            let map = val.as_map().unwrap();
            map.iter()
                .find(|(k, _)| k.as_text() == Some("included"))
                .map(|(_, v)| v.as_map().unwrap().len())
                .unwrap_or(0)
        };
        let full_n = included_len(&full.result);
        let incr_n = included_len(&incr.result);
        assert!(
            incr_n < full_n,
            "incremental ({}) must be smaller than full ({})",
            incr_n,
            full_n
        );
    }

    /// EXTENSION-REVISION v3.6 §4.4.19: fetch-diff is unambiguously
    /// executor-local — cross-peer dispatch MUST NOT be rejected. The
    /// earlier defensive guard inherited framing from the deferred
    /// PROPOSAL-REVISION-DIFF-SINCE-LOCAL-HEAD (a different op with
    /// ambiguous-local semantics); v3.6 rescinded it. Regression guard
    /// against accidentally re-introducing the gate.
    #[tokio::test]
    async fn test_fetch_diff_accepts_cross_peer_dispatch() {
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        put_entity(store.as_ref(), li.as_ref(), "data/a", "alpha");
        handler
            .handle(&make_ctx("commit", make_params("data/", vec![])))
            .await
            .unwrap();

        let mut ctx = make_ctx("fetch-diff", fetch_diff_params("data/", None));
        ctx.is_external = true;

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_OK,
            "fetch-diff MUST accept cross-peer dispatch per v3.6 §4.4.19"
        );
    }

    #[tokio::test]
    async fn test_fetch_diff_no_local_state() {
        // §4.4.19: no revision head bound for prefix → 404 no_local_state.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        let ctx = make_ctx("fetch-diff", fetch_diff_params("data/", None));
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);

        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let code = val
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .unwrap()
            .1
            .as_text()
            .unwrap()
            .to_string();
        assert_eq!(code, "no_local_state");
    }

    #[tokio::test]
    async fn test_fetch_diff_base_not_found() {
        // §4.4.19: base hash absent from local store → 404 base_not_found.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        put_entity(store.as_ref(), li.as_ref(), "data/a", "alpha");
        handler.handle(&make_ctx("commit", make_params("data/", vec![]))).await.unwrap();

        // Use a clearly bogus base hash (zero-type, all-ones digest).
        let bogus = Hash::compute("test/type", b"some-bogus-data-that-is-never-stored");
        let ctx = make_ctx("fetch-diff", fetch_diff_params("data/", Some(bogus)));
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);

        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let code = val
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .unwrap()
            .1
            .as_text()
            .unwrap()
            .to_string();
        assert_eq!(code, "base_not_found");
    }

    #[tokio::test]
    async fn test_fetch_diff_base_not_a_version() {
        // §4.4.19: base hash resolves but isn't a revision entry → 400.
        let (store, li) = make_stores();
        let handler = make_handler(store.clone(), li.clone());

        put_entity(store.as_ref(), li.as_ref(), "data/a", "alpha");
        handler.handle(&make_ctx("commit", make_params("data/", vec![]))).await.unwrap();

        // Insert a non-revision entity into the store, use its hash as base.
        let bogus_data = entity_ecf::to_ecf(&entity_ecf::text("not-a-version"));
        let bogus_entity = Entity::new("test/bogus", bogus_data).unwrap();
        let bogus_hash = store.put(bogus_entity).unwrap();

        let ctx = make_ctx("fetch-diff", fetch_diff_params("data/", Some(bogus_hash)));
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);

        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let code = val
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .unwrap()
            .1
            .as_text()
            .unwrap()
            .to_string();
        assert_eq!(code, "base_not_a_version");
    }
}
