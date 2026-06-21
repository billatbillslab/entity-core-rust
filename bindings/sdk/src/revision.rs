//! Typed wrapper for `system/revision` extension operations.
//!
//! Per `SDK-EXTENSION-OPERATIONS.md §4` (v0.7). Reached via
//! [`PeerContext::revision`].
//!
//! ## Coverage
//!
//! Wraps the consumer-facing ops: `commit`, `status`, `log`, `resolve`,
//! `merge`, `fetch`, `fetch-diff`, `fetch-entities`, `config`,
//! `merge-config`. Ancillary git-style ops (`branch`, `tag`,
//! `checkout`, `cherry-pick`, `revert`, `push`, `pull`, `find-ancestor`,
//! `diff`) are reachable through the raw `PeerContext::execute` path
//! and can be wrapped if consumer demand materializes.
//!
//! Result shapes follow the handler-side wire — most ops return a
//! bare `system/revision/{op}-result` map; `log`, `fetch`,
//! `fetch-diff`, and `fetch-entities` use the `system/envelope`
//! carrier (`{root, included?}`) because they ship trie/version
//! entities alongside the bare result.
//!
//! ## Feature gating
//!
//! Available only when `entity-sdk` is built with the `revision`
//! feature enabled.

use crate::sdk::{PeerContext, SdkError};
use entity_entity::Entity;
use entity_handler::ExecuteOptions;
use entity_hash::Hash;

/// Decoded result of `system/revision:commit`. Wire shape per the
/// authoritative handler spec EXTENSION-REVISION §4.3.1: `{version, root}`.
/// `parent` is an SDK-side convenience, not carried on the wire (always
/// `None` after the G5 revert — see docs/SPEC-AMBIGUITIES.md).
#[derive(Debug, Clone)]
pub struct CommitResult {
    /// Hash of the version entry just created (wire field `version`).
    pub version: Hash,
    /// Root of the snapshot trie referenced by `version` (wire field `root`).
    pub root: Hash,
    /// Previous HEAD. Not on the wire per §4.3.1; always `None`.
    pub parent: Option<Hash>,
}

/// Decoded result of `system/revision:status`.
#[derive(Debug, Clone)]
pub struct RevisionStatus {
    /// Current HEAD version hash for the prefix (`None` if the prefix
    /// has never been committed).
    pub head: Option<Hash>,
    /// Count of unresolved merge conflicts under this prefix.
    pub conflicts: u64,
}

/// Decoded result of `system/revision:log`. Per `EXTENSION-REVISION`
/// §4.3 walk-history form. The handler walks backwards from HEAD up
/// to `limit` entries (default 50) and stops at the optional `since`
/// version anchor.
#[derive(Debug, Clone)]
pub struct RevisionLog {
    /// Prefix as echoed by the handler.
    pub prefix: String,
    /// Walk results, newest-first — the most recent version is
    /// `versions[0]`, the oldest within the window is the last entry.
    /// Empty when the prefix has never been committed.
    pub versions: Vec<Hash>,
    /// `true` when the walk hit the limit before reaching `since` or
    /// the parentless root. Callers paginate by passing the last
    /// returned hash as `since` on the next call.
    pub has_more: bool,
}

/// Decoded result of `system/revision:resolve`. Per `EXTENSION-
/// REVISION §4.3.10` (R2).
#[derive(Debug, Clone)]
pub struct RevisionResolveResult {
    /// Conflict path as supplied by the caller.
    pub path: String,
    /// Count of conflicts remaining under the prefix after this
    /// resolution. Zero means the prefix is clean.
    pub remaining_conflicts: u64,
    /// The hash the caller chose. `None` when the caller resolved-by-
    /// deletion (unbound the path).
    pub resolved: Option<Hash>,
}

/// Decoded result of `system/revision:checkout`. Per `EXTENSION-
/// REVISION §4.3.11` (R3). Detached-HEAD checkout reads the version
/// entry at `target_version` and rewrites the live tree under
/// `prefix` to match its trie snapshot, then advances HEAD to that
/// version. The handler returns the post-op HEAD (which may differ
/// from `target_version` under `auto_version=on` when checkout
/// triggers a new version), plus cascade warnings for paths the
/// snapshot couldn't cleanly restore and a flag indicating whether
/// the live tree had uncommitted writes that were overwritten.
#[derive(Debug, Clone)]
pub struct RevisionCheckoutResult {
    /// Post-op HEAD hash for the prefix. Equal to `target_version`
    /// in the common case; may differ when checkout creates a new
    /// version (e.g., auto-versioned prefix recording the checkout).
    pub head: Hash,
    /// The version the caller asked to check out (round-tripped).
    pub target_version: Hash,
    /// Branch name if the checkout landed on a named branch; `None`
    /// for detached-HEAD checkouts.
    pub branch: Option<String>,
    /// Per-path warnings emitted by the snapshot apply — paths that
    /// were in the snapshot but couldn't be cleanly restored
    /// (handler-managed paths, capability denials, etc.).
    pub cascade_warnings: Vec<String>,
    /// `true` if the live tree had pending writes under `prefix`
    /// when checkout fired. Those writes were overwritten by the
    /// snapshot apply; surface to the user as data-loss warning.
    pub uncommitted_changes: bool,
}

/// Decoded result of `system/revision:merge`. Per `EXTENSION-REVISION
/// §4.4.4`. The `status` string discriminates the outcome — all other
/// fields are conditional on which status fired.
///
/// Status vocabulary (handler-side):
/// - `already_in_sync` — local HEAD == remote_version. Nothing done.
/// - `already_ahead` — local already contains remote_version. Nothing done.
/// - `fast_forward` — local was strictly behind; HEAD advanced. `version` = the new HEAD.
/// - `would_merge` / `would_conflict` — dry-run preview shapes.
/// - `merged` / `merged_with_conflicts` — three-way merge committed; `version` = the merge version.
/// - `converged_identical` — divergent ancestry but trie roots match. Nothing done.
/// - `oscillation_detected` — merge would walk back to a recent ancestor; rejected.
#[derive(Debug, Clone)]
pub struct MergeResult {
    /// Outcome discriminator — see status vocabulary above.
    pub status: String,
    /// New version hash, present when status is `fast_forward`,
    /// `merged`, `merged_with_conflicts`, or the `would_merge` dry-run
    /// preview's anticipated version.
    pub version: Option<Hash>,
    /// Conflict paths (path under the prefix) — non-empty when status
    /// is `would_conflict` or `merged_with_conflicts`.
    pub conflicts: Vec<String>,
    /// Number of paths that received a merged binding (set + retained).
    pub merged_count: u64,
    /// Number of paths that were unbound as part of the merge.
    pub deleted_count: u64,
}

/// Decoded result of `system/revision:fetch` per `EXTENSION-REVISION
/// §4.4.7`. The handler walks history backwards from HEAD up to
/// `depth` entries (default 50) optionally stopping at `since`, and
/// ships back the version entries + their root trie nodes via the
/// `system/envelope` carrier.
///
/// Use case: a peer pulling a remote prefix wants the version chain
/// + the roots so it can plan a `fetch-entities` follow-up for any
/// missing leaves.
#[derive(Debug, Clone)]
pub struct RevisionFetch {
    /// Current HEAD for the prefix on the remote peer, or `None` if
    /// the prefix has never been committed there.
    pub head: Option<Hash>,
    /// Version hashes newest-first; up to `depth` entries.
    pub versions: Vec<Hash>,
    /// `true` if the walk hit the depth cap before exhausting history.
    pub has_more: bool,
    /// Trie + version entities the caller can install into its content
    /// store before redirecting HEAD.
    pub included: std::collections::HashMap<Hash, Entity>,
}

/// Decoded result of `system/revision:fetch-entities` per
/// `EXTENSION-REVISION §4.4.21`. Caller supplies a `snapshot` (a trie
/// root that the responding peer has stored under some version) and a
/// list of `hashes`; the handler returns which were `found` (with
/// entities in `included`) and which were `missing`.
///
/// Used after `fetch` to pull the leaf closure for a snapshot the
/// caller is about to point HEAD at.
#[derive(Debug, Clone)]
pub struct RevisionFetchEntities {
    /// Hashes that the handler had under the snapshot and shipped via
    /// `included`.
    pub found: Vec<Hash>,
    /// Hashes the handler could not satisfy (either not reachable from
    /// `snapshot` or not in its content store).
    pub missing: Vec<Hash>,
    /// Entities keyed by content hash — the union of `found` hashes
    /// the handler had locally.
    pub included: std::collections::HashMap<Hash, Entity>,
}

/// Input for `system/revision:config` (set action). Mirrors the
/// `system/revision/config` entity schema — see `EXTENSION-REVISION
/// §2.1` + `engine::RevisionConfig`.
///
/// Wrappers encode this into the `config` field of the params entity;
/// the handler decodes + validates it (rejecting e.g. unknown
/// `merge_order` values or auto-version configs that don't exclude
/// required paths).
#[derive(Debug, Clone)]
pub struct RevisionConfigInput {
    /// Storage-path prefix this config applies to (e.g.
    /// `/peer-X/knowledge/`). Required.
    pub prefix: String,
    /// When `true`, every tree.put under this prefix triggers an
    /// auto-version commit. Defaults to `false`.
    pub auto_version: bool,
    /// `"deterministic"` (default) or `"caller-perspective"` —
    /// PROPOSAL-REVISION-AUTO-VERSION-FIX §6D.1.
    pub merge_order: Option<String>,
    /// Minimum merge-cycle length to flag as oscillation. Clamped to
    /// `>= 2` by the handler. Defaults to 8 when absent.
    pub oscillation_depth: Option<u64>,
    /// Paths under this prefix to exclude from auto-version. Required
    /// to include the §6D.4 required-exclude set (`system/revision`,
    /// `system/tree/root`, etc.) when those fall under `prefix`.
    pub exclude: Vec<String>,
    /// Entity types to exclude from auto-version.
    pub exclude_types: Vec<String>,
    /// `"warn"` (default), `"allow"`, or `"reject"` per §6A.4.
    pub checkout_under_auto_version: Option<String>,
}

/// Decoded result of `system/revision:config` (set or delete). Per
/// `system/revision/config-result` schema.
#[derive(Debug, Clone)]
pub struct ConfigResult {
    /// Tree path the config landed at (or was deleted from).
    pub config_path: String,
    /// Content hash of the new config entity. `None` on delete.
    pub config_hash: Option<Hash>,
    /// Prior config hash at `config_path` (if any).
    pub previous_hash: Option<Hash>,
    /// Path of the tracking-config sidecar (`system/tree/tracking-
    /// config/...`), present only when the config write toggled
    /// auto-version on or off.
    pub tracking_config_path: Option<String>,
    /// `"created"`, `"updated"`, or `"deleted"` — present only when
    /// `tracking_config_path` is.
    pub tracking_config_action: Option<String>,
}

/// Input for `system/revision:merge-config` (set action). The handler
/// rejects writes whose `deletion_resolution` is `"lww"` or
/// `"keep-both"` with 400 `invalid_strategy` per `EXTENSION-REVISION
/// §2.3`.
///
/// Valid `deletion_resolution` values:
/// `preserve-on-conflict` | `deletion-wins` | `three-way-fallthrough`
/// | `deterministic` | a `<handler-path>` string for custom resolvers.
#[derive(Debug, Clone)]
pub struct MergeConfigInput {
    /// Glob-style pattern this config matches. Required.
    pub pattern: String,
    /// Merge strategy name (e.g. `"three-way"`, `"source-wins"`,
    /// `"target-wins"`). Optional.
    pub strategy: Option<String>,
    /// Behavior when only one side has a binding at a path. See doc
    /// above for valid values.
    pub deletion_resolution: Option<String>,
}

/// Decoded result of `system/revision:merge-config` (set or delete).
/// Per `system/revision/merge-config-result` schema (§4.4.18).
#[derive(Debug, Clone)]
pub struct MergeConfigResult {
    /// Tree path the merge-config landed at (or was deleted from).
    pub path: String,
    /// Content hash of the merge-config entity. `None` on delete.
    pub hash: Option<Hash>,
    /// `"set"`, `"deleted"`, or `"no_change"`.
    pub status: String,
}

/// Decoded result of `system/revision:fetch-diff` per `EXTENSION-
/// REVISION §4.3` Amendment C.1 + `PROPOSAL-CONVERGENT-MIRRORING §2.3`.
///
/// Returns the closure of trie entities reachable from the local
/// peer's current HEAD version but **not** reachable from `base`
/// (the version the caller already has). When `base` is `None`,
/// returns the full closure.
///
/// **MUST be invoked locally**, not cross-peer (D4). The handler
/// reads receiver-local state; cross-peer dispatch would return the
/// executor's diff, not the caller's. The wrapper dispatches via
/// `PeerContext::execute` which is local; cross-peer use would set
/// `ctx.is_external` and the handler would 400 reject.
#[derive(Debug, Clone)]
pub struct RevisionFetchDiff {
    /// The trie root the diff is computed against (= the local peer's
    /// HEAD trie root for the prefix).
    pub root: Hash,
    /// Trie + leaf entities making up the closure. Caller's typical
    /// use: persist all of these into their local content store
    /// before pointing their HEAD at `root`.
    pub included: std::collections::HashMap<Hash, Entity>,
}

/// Typed accessor for `system/revision` operations.
///
/// Created via [`PeerContext::revision`]. Borrows from the
/// `PeerContext`; futures returned by methods are `'static`.
pub struct RevisionOps<'a> {
    ctx: &'a PeerContext,
}

impl<'a> RevisionOps<'a> {
    pub(crate) fn new(ctx: &'a PeerContext) -> Self {
        Self { ctx }
    }

    /// Snapshot current tree state under `prefix` as a new version.
    /// Builds a Merkle trie from the live entities under `prefix`,
    /// writes a version entry `{root, parents}`, and updates HEAD.
    /// See `SDK-EXT-OPS §4` and `EXTENSION-REVISION §4.4.2` for
    /// handler-side semantics.
    ///
    /// Returns the new version's hash plus its trie root. The `parent`
    /// field carries the previous HEAD (or `None` for the first
    /// commit).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn commit(
        &self,
        prefix: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<CommitResult, SdkError>> + Send + 'static {
        let params = build_prefix_params("system/revision/commit-params", prefix.into());
        let fut = self.ctx.execute("system/revision", "commit", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:commit") {
                return Err(err);
            }
            decode_commit_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn commit(
        &self,
        prefix: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<CommitResult, SdkError>> + 'static {
        let params = build_prefix_params("system/revision/commit-params", prefix.into());
        let fut = self.ctx.execute("system/revision", "commit", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:commit") {
                return Err(err);
            }
            decode_commit_result(&result.result)
        }
    }

    /// Read current revision state for `prefix`: HEAD pointer and
    /// outstanding-conflict count. Cheap dispatch — useful for
    /// "what's my current version?" probes before a commit/merge.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn status(
        &self,
        prefix: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<RevisionStatus, SdkError>> + Send + 'static {
        let params = build_prefix_params("system/revision/status-params", prefix.into());
        let fut = self.ctx.execute("system/revision", "status", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:status") {
                return Err(err);
            }
            decode_status_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn status(
        &self,
        prefix: impl Into<String>,
    ) -> impl std::future::Future<Output = Result<RevisionStatus, SdkError>> + 'static {
        let params = build_prefix_params("system/revision/status-params", prefix.into());
        let fut = self.ctx.execute("system/revision", "status", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:status") {
                return Err(err);
            }
            decode_status_result(&result.result)
        }
    }

    /// Walk the version history under `prefix` from HEAD backwards.
    /// Per `EXTENSION-REVISION §4.3` walk-history form.
    ///
    /// `limit` caps the number of versions returned (default 50 on the
    /// handler when `None`). `since` is an optional anchor — the walk
    /// stops when it reaches that version. Use the last returned hash
    /// as the next call's `since` for backwards pagination.
    ///
    /// Returns an empty `versions` array when the prefix has never
    /// been committed; `has_more` is `false` in that case.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn log(
        &self,
        prefix: impl Into<String>,
        limit: Option<usize>,
        since: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionLog, SdkError>> + Send + 'static {
        let params = build_log_params(prefix.into(), limit, since);
        let fut = self.ctx.execute("system/revision", "log", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:log") {
                return Err(err);
            }
            decode_log_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn log(
        &self,
        prefix: impl Into<String>,
        limit: Option<usize>,
        since: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionLog, SdkError>> + 'static {
        let params = build_log_params(prefix.into(), limit, since);
        let fut = self.ctx.execute("system/revision", "log", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:log") {
                return Err(err);
            }
            decode_log_result(&result.result)
        }
    }

    /// Resolve a merge conflict under `prefix` at `path`. Per
    /// `EXTENSION-REVISION §4.3.10` (R2).
    ///
    /// `resolved`:
    /// - `Some(hash)` — bind `path` to the chosen entity. The handler
    ///   verifies the hash exists in the content store; missing →
    ///   `404 resolved_not_found`.
    /// - `None` — **resolve-by-deletion**: unbind `path` from the
    ///   tree (the chosen resolution is "this path should not exist").
    ///
    /// Either way, the conflict marker at `system/revision/conflicts/
    /// {prefix}/{path}` is removed and the remaining-conflicts count
    /// for the prefix decrements by one. `404 no_conflict` when there
    /// is no pending conflict at the given path.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn resolve(
        &self,
        prefix: impl Into<String>,
        path: impl Into<String>,
        resolved: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionResolveResult, SdkError>>
    + Send
    + 'static {
        let params = build_resolve_params(prefix.into(), path.into(), resolved);
        let fut = self
            .ctx
            .execute("system/revision", "resolve", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:resolve") {
                return Err(err);
            }
            decode_resolve_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn resolve(
        &self,
        prefix: impl Into<String>,
        path: impl Into<String>,
        resolved: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionResolveResult, SdkError>> + 'static {
        let params = build_resolve_params(prefix.into(), path.into(), resolved);
        let fut = self
            .ctx
            .execute("system/revision", "resolve", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:resolve") {
                return Err(err);
            }
            decode_resolve_result(&result.result)
        }
    }

    /// Detached-HEAD checkout — restore the live tree under `prefix`
    /// to the snapshot recorded at `target_version` and advance HEAD.
    /// Per `EXTENSION-REVISION §4.3.11` (R3).
    ///
    /// The handler reads the version entry at `target_version`, walks
    /// its trie root, and rewrites the live tree to match. Paths in
    /// the snapshot that can't be cleanly restored (handler-managed
    /// paths, capability mismatches) emit `cascade_warnings`. If the
    /// live tree had uncommitted writes under `prefix`, the
    /// `uncommitted_changes` flag fires — those writes are overwritten.
    ///
    /// Branch selection is via the version graph; this op is the
    /// detached-HEAD form (no branch argument). If the resulting HEAD
    /// is on a named branch, the `branch` field carries the name.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn checkout(
        &self,
        prefix: impl Into<String>,
        target_version: Hash,
    ) -> impl std::future::Future<Output = Result<RevisionCheckoutResult, SdkError>>
    + Send
    + 'static {
        let params = build_checkout_params(prefix.into(), target_version);
        let fut = self
            .ctx
            .execute("system/revision", "checkout", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:checkout") {
                return Err(err);
            }
            decode_checkout_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn checkout(
        &self,
        prefix: impl Into<String>,
        target_version: Hash,
    ) -> impl std::future::Future<Output = Result<RevisionCheckoutResult, SdkError>> + 'static {
        let params = build_checkout_params(prefix.into(), target_version);
        let fut = self
            .ctx
            .execute("system/revision", "checkout", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:checkout") {
                return Err(err);
            }
            decode_checkout_result(&result.result)
        }
    }

    /// Fetch the closure of trie + leaf entities reachable from the
    /// local peer's HEAD for `prefix` but not from `base`. Per
    /// Amendment C.1 + `PROPOSAL-CONVERGENT-MIRRORING §2.3`.
    ///
    /// `base = None` returns the full closure under HEAD.
    ///
    /// **Locality requirement (D4):** this op MUST NOT be cross-peer
    /// dispatched — the handler reads receiver-local state and would
    /// return the executor's diff under a cross-peer call. The SDK's
    /// `PeerContext::execute` is local so this wrapper is safe; if
    /// you proxy through a remote target, the handler 400-rejects.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn fetch_diff(
        &self,
        prefix: impl Into<String>,
        base: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionFetchDiff, SdkError>> + Send + 'static
    {
        let params = build_fetch_diff_params(prefix.into(), base);
        let fut = self
            .ctx
            .execute("system/revision", "fetch-diff", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:fetch-diff") {
                return Err(err);
            }
            decode_fetch_diff_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn fetch_diff(
        &self,
        prefix: impl Into<String>,
        base: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionFetchDiff, SdkError>> + 'static {
        let params = build_fetch_diff_params(prefix.into(), base);
        let fut = self
            .ctx
            .execute("system/revision", "fetch-diff", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:fetch-diff") {
                return Err(err);
            }
            decode_fetch_diff_result(&result.result)
        }
    }

    /// Merge `remote_version` into the local HEAD for `prefix`. Per
    /// `EXTENSION-REVISION §4.4.4`.
    ///
    /// - `strategy` — `"three-way"` (default), `"source-wins"`,
    ///   `"target-wins"`, `"keep-both"`, `"manual"`. The handler
    ///   defaults to `"three-way"` when `None`.
    /// - `dry_run = true` — compute the outcome without writing;
    ///   status becomes `would_merge` / `would_conflict` and no
    ///   version is created.
    /// - `merge_order` — `"deterministic"` (default) or
    ///   `"caller-perspective"`; usually left `None` to inherit the
    ///   prefix config.
    ///
    /// Returns a [`MergeResult`] whose `status` discriminates the
    /// outcome (in-sync / ahead / fast-forward / merged / conflicts /
    /// oscillation). All other fields are conditional on status.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn merge(
        &self,
        prefix: impl Into<String>,
        remote_version: Hash,
        strategy: Option<String>,
        dry_run: bool,
        merge_order: Option<String>,
    ) -> impl std::future::Future<Output = Result<MergeResult, SdkError>> + Send + 'static {
        let params = build_merge_params(prefix.into(), remote_version, strategy, dry_run, merge_order);
        let fut = self
            .ctx
            .execute("system/revision", "merge", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:merge") {
                return Err(err);
            }
            decode_merge_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn merge(
        &self,
        prefix: impl Into<String>,
        remote_version: Hash,
        strategy: Option<String>,
        dry_run: bool,
        merge_order: Option<String>,
    ) -> impl std::future::Future<Output = Result<MergeResult, SdkError>> + 'static {
        let params = build_merge_params(prefix.into(), remote_version, strategy, dry_run, merge_order);
        let fut = self
            .ctx
            .execute("system/revision", "merge", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:merge") {
                return Err(err);
            }
            decode_merge_result(&result.result)
        }
    }

    /// Fetch the version chain + root trie nodes under `prefix` from
    /// HEAD backwards. Per `EXTENSION-REVISION §4.4.7`.
    ///
    /// `depth` caps the walk (handler default 50 when `None`);
    /// `since` stops the walk at a known anchor (use the last hash
    /// from a prior `fetch` to paginate).
    ///
    /// Returns the version list + the included trie/version entities
    /// — typically followed by `fetch_entities` to fill in any missing
    /// leaves under the trie roots before redirecting HEAD.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn fetch(
        &self,
        prefix: impl Into<String>,
        depth: Option<usize>,
        since: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionFetch, SdkError>> + Send + 'static {
        let params = build_log_params(prefix.into(), depth, since);
        let fut = self.ctx.execute("system/revision", "fetch", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:fetch") {
                return Err(err);
            }
            decode_fetch_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn fetch(
        &self,
        prefix: impl Into<String>,
        depth: Option<usize>,
        since: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionFetch, SdkError>> + 'static {
        let params = build_log_params(prefix.into(), depth, since);
        let fut = self.ctx.execute("system/revision", "fetch", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:fetch") {
                return Err(err);
            }
            decode_fetch_result(&result.result)
        }
    }

    /// Fetch a subset of leaf/trie entities under `snapshot` (a trie
    /// root reachable from `prefix`'s version history). Per
    /// `EXTENSION-REVISION §4.4.21`.
    ///
    /// Returns a [`RevisionFetchEntities`] partitioning the supplied
    /// `hashes` into `found` (with entities under `included`) vs
    /// `missing` (unreachable from `snapshot` or absent from the
    /// content store). Used after `fetch` to fill the leaf closure
    /// for a snapshot the caller is about to point HEAD at.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn fetch_entities(
        &self,
        prefix: impl Into<String>,
        snapshot: Hash,
        hashes: Vec<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionFetchEntities, SdkError>> + Send + 'static {
        let params = build_fetch_entities_params(prefix.into(), snapshot, hashes);
        let fut = self
            .ctx
            .execute("system/revision", "fetch-entities", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:fetch-entities") {
                return Err(err);
            }
            decode_fetch_entities_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn fetch_entities(
        &self,
        prefix: impl Into<String>,
        snapshot: Hash,
        hashes: Vec<Hash>,
    ) -> impl std::future::Future<Output = Result<RevisionFetchEntities, SdkError>> + 'static {
        let params = build_fetch_entities_params(prefix.into(), snapshot, hashes);
        let fut = self
            .ctx
            .execute("system/revision", "fetch-entities", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:fetch-entities") {
                return Err(err);
            }
            decode_fetch_entities_result(&result.result)
        }
    }

    /// Set a prefix-level revision config (auto-version, merge_order,
    /// excludes, etc.). Per `EXTENSION-REVISION §4.4.16` config-set.
    ///
    /// `expected_hash` is an optional CAS guard — pass the previously
    /// observed hash of the config entity, and the handler will reject
    /// with 409 `config/concurrent-modification` if it has changed.
    /// `None` skips the guard (use for fresh writes).
    ///
    /// The handler validates the config (e.g. rejects unknown
    /// `merge_order` values, missing required excludes when
    /// `auto_version: true`) before writing.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn config_set(
        &self,
        name: impl Into<String>,
        config: RevisionConfigInput,
        expected_hash: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<ConfigResult, SdkError>> + Send + 'static {
        let params = build_config_params(name.into(), "set", Some(config), expected_hash);
        let fut = self.ctx.execute("system/revision", "config", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:config (set)") {
                return Err(err);
            }
            decode_config_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn config_set(
        &self,
        name: impl Into<String>,
        config: RevisionConfigInput,
        expected_hash: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<ConfigResult, SdkError>> + 'static {
        let params = build_config_params(name.into(), "set", Some(config), expected_hash);
        let fut = self.ctx.execute("system/revision", "config", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:config (set)") {
                return Err(err);
            }
            decode_config_result(&result.result)
        }
    }

    /// Delete a prefix-level revision config. The handler also tears
    /// down the tracking-config sidecar if `auto_version` was true.
    /// `expected_hash` is the same CAS guard as in [`Self::config_set`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn config_delete(
        &self,
        name: impl Into<String>,
        expected_hash: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<ConfigResult, SdkError>> + Send + 'static {
        let params = build_config_params(name.into(), "delete", None, expected_hash);
        let fut = self.ctx.execute("system/revision", "config", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:config (delete)") {
                return Err(err);
            }
            decode_config_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn config_delete(
        &self,
        name: impl Into<String>,
        expected_hash: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<ConfigResult, SdkError>> + 'static {
        let params = build_config_params(name.into(), "delete", None, expected_hash);
        let fut = self.ctx.execute("system/revision", "config", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:config (delete)") {
                return Err(err);
            }
            decode_config_result(&result.result)
        }
    }

    /// Set a path-scoped or type-scoped merge-config. Per Amendment
    /// C.2 / `EXTENSION-REVISION §4.4.18`.
    ///
    /// `scope` is `"path"` or `"type"`; `name` identifies the
    /// per-scope entry (e.g. a path-glob or a type name).
    ///
    /// The handler rejects writes whose `deletion_resolution` is
    /// `"lww"` or `"keep-both"` with 400 `invalid_strategy` per §2.3.
    /// Re-issuing identical content returns status `"no_change"`
    /// without a tree write (idempotency).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn merge_config_set(
        &self,
        scope: impl Into<String>,
        name: impl Into<String>,
        config: MergeConfigInput,
        expected_hash: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<MergeConfigResult, SdkError>> + Send + 'static
    {
        let params = build_merge_config_params(
            scope.into(),
            name.into(),
            "set",
            Some(config),
            expected_hash,
        );
        let fut = self
            .ctx
            .execute("system/revision", "merge-config", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:merge-config (set)") {
                return Err(err);
            }
            decode_merge_config_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn merge_config_set(
        &self,
        scope: impl Into<String>,
        name: impl Into<String>,
        config: MergeConfigInput,
        expected_hash: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<MergeConfigResult, SdkError>> + 'static {
        let params = build_merge_config_params(
            scope.into(),
            name.into(),
            "set",
            Some(config),
            expected_hash,
        );
        let fut = self
            .ctx
            .execute("system/revision", "merge-config", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:merge-config (set)") {
                return Err(err);
            }
            decode_merge_config_result(&result.result)
        }
    }

    /// Delete a path/type-scoped merge-config. CAS guard via
    /// `expected_hash` matches [`Self::merge_config_set`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn merge_config_delete(
        &self,
        scope: impl Into<String>,
        name: impl Into<String>,
        expected_hash: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<MergeConfigResult, SdkError>> + Send + 'static
    {
        let params =
            build_merge_config_params(scope.into(), name.into(), "delete", None, expected_hash);
        let fut = self
            .ctx
            .execute("system/revision", "merge-config", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:merge-config (delete)") {
                return Err(err);
            }
            decode_merge_config_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn merge_config_delete(
        &self,
        scope: impl Into<String>,
        name: impl Into<String>,
        expected_hash: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<MergeConfigResult, SdkError>> + 'static {
        let params =
            build_merge_config_params(scope.into(), name.into(), "delete", None, expected_hash);
        let fut = self
            .ctx
            .execute("system/revision", "merge-config", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/revision:merge-config (delete)") {
                return Err(err);
            }
            decode_merge_config_result(&result.result)
        }
    }
}

/// Build a `{prefix: <str>}` params entity for ops that take only a
/// prefix (commit / status / log / etc.). The entity type slot exists
/// per the handler's expectation (it reads `params.data`, not
/// `params.entity_type`, but we name it explicitly for grep-ability).
fn build_prefix_params(entity_type: &str, prefix: String) -> Entity {
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(vec![(
        entity_ecf::text("prefix"),
        entity_ecf::text(&prefix),
    )]));
    Entity::new(entity_type, data)
        .expect("prefix-only params entity construction is infallible")
}

fn decode_commit_result(entity: &Entity) -> Result<CommitResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode commit result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("commit result not a map".into()))?;

    let mut version: Option<Hash> = None;
    let mut root: Option<Hash> = None;
    let mut parent: Option<Hash> = None;

    for (k, v) in map {
        match k.as_text() {
            // EXTENSION-REVISION §4.3.1: commit-result data is {version, root}.
            Some("version") => version = decode_hash_field(v),
            Some("root") => root = decode_hash_field(v),
            Some("parent") => parent = decode_hash_field(v),
            _ => {}
        }
    }

    Ok(CommitResult {
        version: version
            .ok_or_else(|| SdkError::HandlerError("commit result missing `version`".into()))?,
        root: root
            .ok_or_else(|| SdkError::HandlerError("commit result missing `root`".into()))?,
        parent,
    })
}

fn decode_status_result(entity: &Entity) -> Result<RevisionStatus, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode status result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("status result not a map".into()))?;

    let mut head: Option<Hash> = None;
    let mut conflicts: u64 = 0;

    for (k, v) in map {
        match k.as_text() {
            Some("head") => head = decode_hash_field(v),
            Some("conflicts") => {
                if let ciborium::Value::Integer(i) = v {
                    let signed: i128 = (*i).into();
                    if signed >= 0 {
                        conflicts = signed as u64;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(RevisionStatus { head, conflicts })
}

fn decode_hash_field(v: &ciborium::Value) -> Option<Hash> {
    match v {
        ciborium::Value::Bytes(b) => Hash::from_bytes(b).ok(),
        _ => None,
    }
}

/// Build the log-params body. Per `EXTENSION-REVISION §4.3`: `prefix`
/// is required; `limit` and `since` are optional. ECF-sorted order:
/// `limit`, `prefix`, `since`.
fn build_log_params(prefix: String, limit: Option<usize>, since: Option<Hash>) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    if let Some(n) = limit {
        fields.push((entity_ecf::text("limit"), entity_ecf::integer(n as i64)));
    }
    fields.push((entity_ecf::text("prefix"), entity_ecf::text(&prefix)));
    if let Some(h) = since {
        fields.push((
            entity_ecf::text("since"),
            ciborium::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/revision/log-params", data)
        .expect("log-params entity construction is infallible")
}

fn decode_log_result(entity: &Entity) -> Result<RevisionLog, SdkError> {
    // The log handler returns a system/envelope wrapper —
    // {root: <log-result entity inlined>, included?: {...}}.
    // Unwrap the root and decode the actual log-result body.
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode log envelope: {}", e)))?;
    let envelope_map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("log envelope not a map".into()))?;

    let root_value = envelope_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("root") { Some(v) } else { None })
        .ok_or_else(|| SdkError::HandlerError("log envelope missing root".into()))?;
    let root_map = root_value
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("log root not a map".into()))?;

    // root is {content_hash, data, type}; the actual log-result body
    // lives under `data`.
    let body = root_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("data") { Some(v) } else { None })
        .ok_or_else(|| SdkError::HandlerError("log root missing data".into()))?;
    let body_map = body
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("log root.data not a map".into()))?;

    let mut prefix: Option<String> = None;
    let mut versions: Vec<Hash> = Vec::new();
    let mut has_more = false;

    for (k, v) in body_map {
        match k.as_text() {
            Some("prefix") => prefix = v.as_text().map(|s| s.to_string()),
            Some("versions") => {
                if let ciborium::Value::Array(arr) = v {
                    for item in arr {
                        if let Some(h) = decode_hash_field(item) {
                            versions.push(h);
                        }
                    }
                }
            }
            Some("has_more") => {
                if let ciborium::Value::Bool(b) = v {
                    has_more = *b;
                }
            }
            _ => {}
        }
    }

    Ok(RevisionLog {
        prefix: prefix
            .ok_or_else(|| SdkError::HandlerError("log result missing prefix".into()))?,
        versions,
        has_more,
    })
}

/// Build the resolve-params body. ECF-sorted order: `path`, `prefix`,
/// `resolved`.
fn build_resolve_params(prefix: String, path: String, resolved: Option<Hash>) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (entity_ecf::text("path"), entity_ecf::text(&path)),
        (entity_ecf::text("prefix"), entity_ecf::text(&prefix)),
    ];
    if let Some(h) = resolved {
        fields.push((
            entity_ecf::text("resolved"),
            ciborium::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/revision/resolve-params", data)
        .expect("resolve-params entity construction is infallible")
}

fn decode_resolve_result(entity: &Entity) -> Result<RevisionResolveResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode resolve result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("resolve result not a map".into()))?;

    let mut path: Option<String> = None;
    let mut remaining_conflicts: u64 = 0;
    let mut resolved: Option<Hash> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("path") => path = v.as_text().map(|s| s.to_string()),
            Some("remaining_conflicts") => {
                if let ciborium::Value::Integer(i) = v {
                    let signed: i128 = (*i).into();
                    if signed >= 0 {
                        remaining_conflicts = signed as u64;
                    }
                }
            }
            Some("resolved") => resolved = decode_hash_field(v),
            _ => {}
        }
    }
    Ok(RevisionResolveResult {
        path: path
            .ok_or_else(|| SdkError::HandlerError("resolve result missing path".into()))?,
        remaining_conflicts,
        resolved,
    })
}

/// Build the checkout-params body. ECF-sorted order: `prefix`,
/// `version` (detached-HEAD form — no branch argument).
fn build_checkout_params(prefix: String, version: Hash) -> Entity {
    let fields: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (entity_ecf::text("prefix"), entity_ecf::text(&prefix)),
        (
            entity_ecf::text("version"),
            ciborium::Value::Bytes(version.to_bytes().to_vec()),
        ),
    ];
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/revision/checkout-params", data)
        .expect("checkout-params entity construction is infallible")
}

/// Decode `system/revision:checkout` result. Wire shape per
/// `extensions/revision/src/lib.rs:1372+`:
///   `{head, status: "checked_out", target_version, version (compat),
///     branch?, cascade_warnings?, uncommitted_changes?, warning?}`
fn decode_checkout_result(entity: &Entity) -> Result<RevisionCheckoutResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode checkout result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("checkout result not a map".into()))?;

    let mut head: Option<Hash> = None;
    let mut target_version: Option<Hash> = None;
    let mut branch: Option<String> = None;
    let mut cascade_warnings: Vec<String> = Vec::new();
    let mut uncommitted_changes = false;

    for (k, v) in map {
        match k.as_text() {
            Some("head") => head = decode_hash_field(v),
            Some("target_version") => target_version = decode_hash_field(v),
            Some("branch") => branch = v.as_text().map(|s| s.to_string()),
            Some("cascade_warnings") => {
                if let ciborium::Value::Array(arr) = v {
                    for item in arr {
                        if let Some(s) = item.as_text() {
                            cascade_warnings.push(s.to_string());
                        }
                    }
                }
            }
            Some("uncommitted_changes") => {
                if let ciborium::Value::Bool(b) = v {
                    uncommitted_changes = *b;
                }
            }
            _ => {}
        }
    }

    Ok(RevisionCheckoutResult {
        head: head
            .ok_or_else(|| SdkError::HandlerError("checkout result missing head".into()))?,
        target_version: target_version.ok_or_else(|| {
            SdkError::HandlerError("checkout result missing target_version".into())
        })?,
        branch,
        cascade_warnings,
        uncommitted_changes,
    })
}

/// Build the fetch-diff-params body. ECF-sorted order: `base`,
/// `prefix`.
fn build_fetch_diff_params(prefix: String, base: Option<Hash>) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    if let Some(h) = base {
        fields.push((
            entity_ecf::text("base"),
            ciborium::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    fields.push((entity_ecf::text("prefix"), entity_ecf::text(&prefix)));
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/revision/fetch-diff-params", data)
        .expect("fetch-diff-params entity construction is infallible")
}

fn decode_fetch_diff_result(entity: &Entity) -> Result<RevisionFetchDiff, SdkError> {
    // fetch-diff returns a system/envelope wrapper:
    //   { root: <snapshot-pointer { root: bytes }>, included?: {hash → entity} }
    // The "root" field is an inlined snapshot entity whose data carries
    // a `root: bytes` field pointing at the trie root.
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode fetch-diff envelope: {}", e)))?;
    let envelope_map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("fetch-diff envelope not a map".into()))?;

    let mut included: std::collections::HashMap<Hash, Entity> =
        std::collections::HashMap::new();
    let mut root: Option<Hash> = None;

    for (k, v) in envelope_map {
        match k.as_text() {
            Some("root") => {
                // Inlined snapshot pointer: {content_hash, data, type}.
                let root_map = v
                    .as_map()
                    .ok_or_else(|| SdkError::HandlerError("fetch-diff root not a map".into()))?;
                let snapshot_body = root_map
                    .iter()
                    .find_map(|(kk, vv)| if kk.as_text() == Some("data") { Some(vv) } else { None })
                    .ok_or_else(|| {
                        SdkError::HandlerError("fetch-diff root missing data".into())
                    })?;
                let snapshot_body_map = snapshot_body.as_map().ok_or_else(|| {
                    SdkError::HandlerError("fetch-diff root.data not a map".into())
                })?;
                for (kk, vv) in snapshot_body_map {
                    if kk.as_text() == Some("root") {
                        root = decode_hash_field(vv);
                    }
                }
            }
            Some("included") => {
                let inc_map = v
                    .as_map()
                    .ok_or_else(|| SdkError::HandlerError("included not a map".into()))?;
                for (hash_key, entity_val) in inc_map {
                    let hash = match decode_hash_field(hash_key) {
                        Some(h) => h,
                        None => continue,
                    };
                    let entity_map = match entity_val.as_map() {
                        Some(m) => m,
                        None => continue,
                    };
                    let mut etype: Option<String> = None;
                    let mut edata_val: Option<&ciborium::Value> = None;
                    for (ek, ev) in entity_map {
                        match ek.as_text() {
                            Some("type") => etype = ev.as_text().map(|s| s.to_string()),
                            Some("data") => edata_val = Some(ev),
                            _ => {}
                        }
                    }
                    if let (Some(t), Some(d)) = (etype, edata_val) {
                        // Re-encode the inlined data value back to ECF
                        // bytes — same fidelity contract as
                        // identity::decode_create_att_result.
                        let bytes = entity_ecf::to_ecf(d);
                        if let Ok(e) = Entity::new(&t, bytes) {
                            included.insert(hash, e);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(RevisionFetchDiff {
        root: root.ok_or_else(|| {
            SdkError::HandlerError("fetch-diff envelope missing snapshot root".into())
        })?,
        included,
    })
}

/// Build the merge-params body. ECF-sorted order: `dry_run`,
/// `merge_order`, `prefix`, `remote_version`, `strategy`.
fn build_merge_params(
    prefix: String,
    remote_version: Hash,
    strategy: Option<String>,
    dry_run: bool,
    merge_order: Option<String>,
) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    if dry_run {
        fields.push((entity_ecf::text("dry_run"), ciborium::Value::Bool(true)));
    }
    if let Some(mo) = merge_order {
        fields.push((entity_ecf::text("merge_order"), entity_ecf::text(&mo)));
    }
    fields.push((entity_ecf::text("prefix"), entity_ecf::text(&prefix)));
    fields.push((
        entity_ecf::text("remote_version"),
        ciborium::Value::Bytes(remote_version.to_bytes().to_vec()),
    ));
    if let Some(s) = strategy {
        fields.push((entity_ecf::text("strategy"), entity_ecf::text(&s)));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/revision/merge-params", data)
        .expect("merge-params entity construction is infallible")
}

fn decode_merge_result(entity: &Entity) -> Result<MergeResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode merge result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("merge result not a map".into()))?;

    let mut status: Option<String> = None;
    let mut version: Option<Hash> = None;
    let mut conflicts: Vec<String> = Vec::new();
    let mut merged_count: u64 = 0;
    let mut deleted_count: u64 = 0;

    for (k, v) in map {
        match k.as_text() {
            Some("status") => status = v.as_text().map(|s| s.to_string()),
            Some("version") => version = decode_hash_field(v),
            Some("conflicts") => {
                if let ciborium::Value::Array(arr) = v {
                    for item in arr {
                        if let Some(s) = item.as_text() {
                            conflicts.push(s.to_string());
                        }
                    }
                }
            }
            Some("merged_count") => {
                if let ciborium::Value::Integer(i) = v {
                    let signed: i128 = (*i).into();
                    if signed >= 0 {
                        merged_count = signed as u64;
                    }
                }
            }
            Some("deleted_count") => {
                if let ciborium::Value::Integer(i) = v {
                    let signed: i128 = (*i).into();
                    if signed >= 0 {
                        deleted_count = signed as u64;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(MergeResult {
        status: status
            .ok_or_else(|| SdkError::HandlerError("merge result missing status".into()))?,
        version,
        conflicts,
        merged_count,
        deleted_count,
    })
}

fn decode_fetch_result(entity: &Entity) -> Result<RevisionFetch, SdkError> {
    let (root_data, included) = decode_envelope(entity, "fetch")?;

    let mut head: Option<Hash> = None;
    let mut versions: Vec<Hash> = Vec::new();
    let mut has_more = false;

    for (k, v) in root_data {
        match k.as_text() {
            Some("head") => head = decode_hash_field(&v),
            Some("versions") => {
                if let ciborium::Value::Array(arr) = v {
                    for item in arr {
                        if let Some(h) = decode_hash_field(&item) {
                            versions.push(h);
                        }
                    }
                }
            }
            Some("has_more") => {
                if let ciborium::Value::Bool(b) = v {
                    has_more = b;
                }
            }
            _ => {}
        }
    }

    Ok(RevisionFetch {
        head,
        versions,
        has_more,
        included,
    })
}

/// Build the fetch-entities-params body. ECF-sorted order:
/// `hashes`, `prefix`, `snapshot`.
fn build_fetch_entities_params(prefix: String, snapshot: Hash, hashes: Vec<Hash>) -> Entity {
    let hash_arr: Vec<ciborium::Value> = hashes
        .into_iter()
        .map(|h| ciborium::Value::Bytes(h.to_bytes().to_vec()))
        .collect();
    let fields = vec![
        (entity_ecf::text("hashes"), ciborium::Value::Array(hash_arr)),
        (entity_ecf::text("prefix"), entity_ecf::text(&prefix)),
        (
            entity_ecf::text("snapshot"),
            ciborium::Value::Bytes(snapshot.to_bytes().to_vec()),
        ),
    ];
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/revision/fetch-entities-params", data)
        .expect("fetch-entities-params entity construction is infallible")
}

fn decode_fetch_entities_result(entity: &Entity) -> Result<RevisionFetchEntities, SdkError> {
    let (root_data, included) = decode_envelope(entity, "fetch-entities")?;

    let mut found: Vec<Hash> = Vec::new();
    let mut missing: Vec<Hash> = Vec::new();

    for (k, v) in root_data {
        match k.as_text() {
            Some("found") => {
                if let ciborium::Value::Array(arr) = v {
                    for item in arr {
                        if let Some(h) = decode_hash_field(&item) {
                            found.push(h);
                        }
                    }
                }
            }
            Some("missing") => {
                if let ciborium::Value::Array(arr) = v {
                    for item in arr {
                        if let Some(h) = decode_hash_field(&item) {
                            missing.push(h);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(RevisionFetchEntities {
        found,
        missing,
        included,
    })
}

/// Build the config-params body. ECF-sorted order: `action`, `config`,
/// `expected_hash`, `name`.
fn build_config_params(
    name: String,
    action: &str,
    config: Option<RevisionConfigInput>,
    expected_hash: Option<Hash>,
) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    fields.push((entity_ecf::text("action"), entity_ecf::text(action)));
    if let Some(c) = config {
        fields.push((entity_ecf::text("config"), encode_revision_config(&c)));
    }
    if let Some(h) = expected_hash {
        fields.push((
            entity_ecf::text("expected_hash"),
            ciborium::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    fields.push((entity_ecf::text("name"), entity_ecf::text(&name)));
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/revision/config-params", data)
        .expect("config-params entity construction is infallible")
}

/// Encode `RevisionConfigInput` as a CBOR map matching the handler's
/// `decode_revision_config` reader. ECF-sorted field order:
/// `auto_version`, `checkout_under_auto_version`, `exclude`,
/// `exclude_types`, `merge_order`, `oscillation_depth`, `prefix`.
fn encode_revision_config(c: &RevisionConfigInput) -> ciborium::Value {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    fields.push((
        entity_ecf::text("auto_version"),
        ciborium::Value::Bool(c.auto_version),
    ));
    if let Some(ref p) = c.checkout_under_auto_version {
        fields.push((
            entity_ecf::text("checkout_under_auto_version"),
            entity_ecf::text(p),
        ));
    }
    if !c.exclude.is_empty() {
        fields.push((
            entity_ecf::text("exclude"),
            ciborium::Value::Array(c.exclude.iter().map(|s| entity_ecf::text(s)).collect()),
        ));
    }
    if !c.exclude_types.is_empty() {
        fields.push((
            entity_ecf::text("exclude_types"),
            ciborium::Value::Array(
                c.exclude_types.iter().map(|s| entity_ecf::text(s)).collect(),
            ),
        ));
    }
    if let Some(ref mo) = c.merge_order {
        fields.push((entity_ecf::text("merge_order"), entity_ecf::text(mo)));
    }
    if let Some(d) = c.oscillation_depth {
        fields.push((
            entity_ecf::text("oscillation_depth"),
            entity_ecf::integer(d as i64),
        ));
    }
    fields.push((entity_ecf::text("prefix"), entity_ecf::text(&c.prefix)));
    ciborium::Value::Map(fields)
}

fn decode_config_result(entity: &Entity) -> Result<ConfigResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode config result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("config result not a map".into()))?;

    let mut config_path: Option<String> = None;
    let mut config_hash: Option<Hash> = None;
    let mut previous_hash: Option<Hash> = None;
    let mut tracking_config_path: Option<String> = None;
    let mut tracking_config_action: Option<String> = None;

    for (k, v) in map {
        match k.as_text() {
            Some("config_path") => config_path = v.as_text().map(|s| s.to_string()),
            Some("config_hash") => config_hash = decode_hash_field(v),
            Some("previous_hash") => previous_hash = decode_hash_field(v),
            Some("tracking_config_path") => {
                tracking_config_path = v.as_text().map(|s| s.to_string())
            }
            Some("tracking_config_action") => {
                tracking_config_action = v.as_text().map(|s| s.to_string())
            }
            _ => {}
        }
    }

    Ok(ConfigResult {
        config_path: config_path
            .ok_or_else(|| SdkError::HandlerError("config result missing config_path".into()))?,
        config_hash,
        previous_hash,
        tracking_config_path,
        tracking_config_action,
    })
}

/// Build the merge-config-params body. ECF-sorted order: `action`,
/// `config`, `expected_hash`, `name`, `scope`.
fn build_merge_config_params(
    scope: String,
    name: String,
    action: &str,
    config: Option<MergeConfigInput>,
    expected_hash: Option<Hash>,
) -> Entity {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    fields.push((entity_ecf::text("action"), entity_ecf::text(action)));
    if let Some(c) = config {
        fields.push((entity_ecf::text("config"), encode_merge_config(&c)));
    }
    if let Some(h) = expected_hash {
        fields.push((
            entity_ecf::text("expected_hash"),
            ciborium::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    fields.push((entity_ecf::text("name"), entity_ecf::text(&name)));
    fields.push((entity_ecf::text("scope"), entity_ecf::text(&scope)));
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/revision/merge-config-params", data)
        .expect("merge-config-params entity construction is infallible")
}

/// Encode `MergeConfigInput` as a CBOR map matching the handler's
/// `validate_merge_config_for_write` reader. ECF-sorted field order:
/// `deletion_resolution`, `pattern`, `strategy`.
fn encode_merge_config(c: &MergeConfigInput) -> ciborium::Value {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    if let Some(ref dr) = c.deletion_resolution {
        fields.push((
            entity_ecf::text("deletion_resolution"),
            entity_ecf::text(dr),
        ));
    }
    fields.push((entity_ecf::text("pattern"), entity_ecf::text(&c.pattern)));
    if let Some(ref s) = c.strategy {
        fields.push((entity_ecf::text("strategy"), entity_ecf::text(s)));
    }
    ciborium::Value::Map(fields)
}

fn decode_merge_config_result(entity: &Entity) -> Result<MergeConfigResult, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode merge-config result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("merge-config result not a map".into()))?;

    let mut path: Option<String> = None;
    let mut hash: Option<Hash> = None;
    let mut status: Option<String> = None;

    for (k, v) in map {
        match k.as_text() {
            Some("path") => path = v.as_text().map(|s| s.to_string()),
            Some("hash") => hash = decode_hash_field(v),
            Some("status") => status = v.as_text().map(|s| s.to_string()),
            _ => {}
        }
    }

    Ok(MergeConfigResult {
        path: path
            .ok_or_else(|| SdkError::HandlerError("merge-config result missing path".into()))?,
        hash,
        status: status
            .ok_or_else(|| SdkError::HandlerError("merge-config result missing status".into()))?,
    })
}

/// Generic envelope decoder for `fetch` and `fetch-entities` results.
/// Both ops wrap a `system/revision/{op}-result` entity inside the
/// `system/envelope` carrier (`{root: <inlined>, included?: {...}}`).
///
/// Returns the inlined root's `data` map (consumed by the op-specific
/// decoder) and the decoded `included` entities. Mirrors the
/// envelope-unwrap pattern in `decode_log_result` and
/// `decode_fetch_diff_result`.
fn decode_envelope(
    entity: &Entity,
    op_name: &str,
) -> Result<
    (
        Vec<(ciborium::Value, ciborium::Value)>,
        std::collections::HashMap<Hash, Entity>,
    ),
    SdkError,
> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode {} envelope: {}", op_name, e)))?;
    let envelope_map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError(format!("{} envelope not a map", op_name)))?;

    let mut root_data: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    let mut included: std::collections::HashMap<Hash, Entity> =
        std::collections::HashMap::new();

    for (k, v) in envelope_map {
        match k.as_text() {
            Some("root") => {
                let root_map = v.as_map().ok_or_else(|| {
                    SdkError::HandlerError(format!("{} envelope root not a map", op_name))
                })?;
                let body = root_map
                    .iter()
                    .find_map(|(kk, vv)| {
                        if kk.as_text() == Some("data") {
                            Some(vv)
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        SdkError::HandlerError(format!("{} envelope root missing data", op_name))
                    })?;
                let body_map = body.as_map().ok_or_else(|| {
                    SdkError::HandlerError(format!("{} envelope root.data not a map", op_name))
                })?;
                root_data = body_map.clone();
            }
            Some("included") => {
                let inc_map = v.as_map().ok_or_else(|| {
                    SdkError::HandlerError(format!("{} envelope included not a map", op_name))
                })?;
                for (hash_key, entity_val) in inc_map {
                    let hash = match decode_hash_field(hash_key) {
                        Some(h) => h,
                        None => continue,
                    };
                    let entity_map = match entity_val.as_map() {
                        Some(m) => m,
                        None => continue,
                    };
                    let mut etype: Option<String> = None;
                    let mut edata_val: Option<&ciborium::Value> = None;
                    for (ek, ev) in entity_map {
                        match ek.as_text() {
                            Some("type") => etype = ev.as_text().map(|s| s.to_string()),
                            Some("data") => edata_val = Some(ev),
                            _ => {}
                        }
                    }
                    if let (Some(t), Some(d)) = (etype, edata_val) {
                        let bytes = entity_ecf::to_ecf(d);
                        if let Ok(e) = Entity::new(&t, bytes) {
                            included.insert(hash, e);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok((root_data, included))
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

    /// Status on a fresh peer with no commits returns `head: None`
    /// and `conflicts: 0`. Proves: scope handle reaches the revision
    /// handler, decode_status_result handles the absent-head shape.
    #[tokio::test(flavor = "current_thread")]
    async fn status_fresh_peer_has_no_head() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/knowledge/", pid);

        let status = ctx
            .revision()
            .status(prefix)
            .await
            .expect("status should dispatch on fresh peer");

        assert!(status.head.is_none(), "fresh peer has no HEAD");
        assert_eq!(status.conflicts, 0, "fresh peer has no conflicts");
    }

    /// Commit on a fresh prefix produces a version + root, and status
    /// then reports that version as HEAD. End-to-end test of the
    /// commit/status pair.
    #[tokio::test(flavor = "current_thread")]
    async fn commit_then_status_returns_head() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/knowledge/", pid);

        // Seed at least one entity under the prefix so commit has
        // something to snapshot. (Empty commits are handler-policy
        // dependent — keep the test prefix non-empty.)
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let entity = Entity::new("app/note", data).unwrap();
        ctx.store().put(&format!("{}note", prefix), entity).unwrap();

        let commit = ctx
            .revision()
            .commit(prefix.clone())
            .await
            .expect("commit should succeed");

        // Verify the result decoded correctly — hashes are non-zero.
        // Hash::to_bytes() returns [u8; HASH_WIRE_LEN] (33 = 1 tag + 32
        // digest). Test against an all-zeros buffer of the same len.
        assert!(
            commit.version.to_bytes().iter().any(|&b| b != 0),
            "version hash should be non-zero"
        );
        assert!(
            commit.root.to_bytes().iter().any(|&b| b != 0),
            "root hash should be non-zero"
        );

        let status = ctx
            .revision()
            .status(prefix)
            .await
            .expect("status should succeed after commit");
        assert_eq!(
            status.head,
            Some(commit.version),
            "status.head equals committed version hash"
        );
    }

    /// `log` on a fresh prefix (no commits) returns an empty version
    /// array with `has_more: false`. Probes: envelope unwrap reaches
    /// the inner log-result body, prefix echoes back, empty-array
    /// path decodes cleanly.
    #[tokio::test(flavor = "current_thread")]
    async fn log_fresh_prefix_is_empty() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/no-commits-here/", pid);
        let log = ctx
            .revision()
            .log(prefix.clone(), None, None)
            .await
            .expect("log should dispatch on fresh prefix");
        assert_eq!(log.prefix, prefix);
        assert!(log.versions.is_empty(), "no commits → no versions");
        assert!(!log.has_more, "fresh prefix → no more pages");
    }

    /// `resolve` against a prefix with no pending conflicts returns
    /// `404 no_conflict`. Probes dispatch + the resolve-params shape.
    #[tokio::test(flavor = "current_thread")]
    async fn resolve_no_conflict_returns_404() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/resolve-clean/", pid);
        let target_hash = Hash::from_bytes(&[0x00u8; 33]).unwrap();
        let r = ctx
            .revision()
            .resolve(prefix, "missing/path", Some(target_hash))
            .await;
        match r {
            Err(SdkError::NotFound { status: 404, .. }) => {}
            other => panic!("expected 404 no_conflict, got {:?}", other),
        }
    }

    /// `fetch_diff` on a prefix with no HEAD returns `404
    /// no_local_state`. Verifies wrapper threads prefix + optional
    /// base through the wire correctly and the envelope-shape
    /// decoder doesn't fire on the error path.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_diff_no_head_returns_404() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/never-committed/", pid);
        let r = ctx.revision().fetch_diff(prefix, None).await;
        match r {
            Err(SdkError::NotFound { status: 404, .. }) => {}
            other => panic!("expected 404 no_local_state, got {:?}", other),
        }
    }

    /// `fetch_diff` after a commit returns an envelope with the HEAD
    /// trie root and the full closure of trie entities under it
    /// (base = None). Probes: envelope unwrap reaches snapshot.root,
    /// included map decodes back into typed Entities.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_diff_after_commit_returns_root_and_included() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/diff-after-commit/", pid);

        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        ctx.store()
            .put(
                &format!("{}note", prefix),
                Entity::new("app/note", data).unwrap(),
            )
            .unwrap();
        let c = ctx
            .revision()
            .commit(prefix.clone())
            .await
            .expect("commit");

        let diff = ctx
            .revision()
            .fetch_diff(prefix, None)
            .await
            .expect("fetch_diff should succeed after commit");

        assert_eq!(
            diff.root, c.root,
            "fetch_diff root equals the commit's trie root"
        );
        assert!(
            !diff.included.is_empty(),
            "full-closure diff must include at least the trie root entity + the note leaf"
        );
        // Every included entity round-trips through Entity::new, so
        // its content_hash equals its key in the map.
        for (key, ent) in &diff.included {
            assert_eq!(
                *key, ent.content_hash,
                "included key must equal entity content_hash"
            );
        }
    }

    /// `log` after two commits returns both versions newest-first.
    /// Verifies envelope decode for the populated case + walk order
    /// per §4.3 (HEAD first, ancestors after).
    #[tokio::test(flavor = "current_thread")]
    async fn log_after_two_commits_lists_both_newest_first() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/knowledge-log/", pid);

        // Seed two entities + two commits.
        let data1 = entity_ecf::to_ecf(&entity_ecf::text("one"));
        ctx.store()
            .put(&format!("{}n1", prefix), Entity::new("app/note", data1).unwrap())
            .unwrap();
        let c1 = ctx
            .revision()
            .commit(prefix.clone())
            .await
            .expect("first commit");

        let data2 = entity_ecf::to_ecf(&entity_ecf::text("two"));
        ctx.store()
            .put(&format!("{}n2", prefix), Entity::new("app/note", data2).unwrap())
            .unwrap();
        let c2 = ctx
            .revision()
            .commit(prefix.clone())
            .await
            .expect("second commit");

        let log = ctx
            .revision()
            .log(prefix.clone(), None, None)
            .await
            .expect("log should succeed after commits");
        assert_eq!(log.prefix, prefix);
        assert_eq!(log.versions.len(), 2, "two commits → two versions");
        assert_eq!(log.versions[0], c2.version, "newest first");
        assert_eq!(log.versions[1], c1.version, "oldest last");
        assert!(!log.has_more, "two commits fit under default limit");
    }

    /// `merge` against a prefix with no HEAD returns 400 `no_head`.
    /// Probes dispatch + merge-params shape on the error path before
    /// the wrapper has to exercise three-way merge against a real
    /// remote (which needs a cross-peer connection).
    #[tokio::test(flavor = "current_thread")]
    async fn merge_no_head_returns_400() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/never-committed-merge/", pid);
        let remote = Hash::from_bytes(&[0x00u8; 33]).unwrap();
        let r = ctx
            .revision()
            .merge(prefix, remote, None, false, None)
            .await;
        match r {
            Err(SdkError::BadRequest { status: 400, .. }) => {}
            other => panic!("expected 400 no_head, got {:?}", other),
        }
    }

    /// `merge` of HEAD against itself returns `already_in_sync` with
    /// no version + no conflicts. Verifies the wrapper threads the
    /// remote_version through correctly and the bare merge-result
    /// decoder handles the no-write happy path.
    #[tokio::test(flavor = "current_thread")]
    async fn merge_self_returns_already_in_sync() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/merge-self/", pid);

        let data = entity_ecf::to_ecf(&entity_ecf::text("seed"));
        ctx.store()
            .put(&format!("{}n", prefix), Entity::new("app/note", data).unwrap())
            .unwrap();
        let c = ctx
            .revision()
            .commit(prefix.clone())
            .await
            .expect("commit");

        let r = ctx
            .revision()
            .merge(prefix, c.version, None, false, None)
            .await
            .expect("merge self should succeed");
        assert_eq!(r.status, "already_in_sync");
        assert!(r.version.is_none());
        assert!(r.conflicts.is_empty());
        assert_eq!(r.merged_count, 0);
        assert_eq!(r.deleted_count, 0);
    }

    /// `fetch` on a fresh prefix returns empty history with `head:
    /// None` and `has_more: false`. Verifies envelope decode for the
    /// no-state path + that the included map is empty.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_fresh_prefix_is_empty() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/never-fetched/", pid);
        let f = ctx
            .revision()
            .fetch(prefix, None, None)
            .await
            .expect("fetch should dispatch on fresh prefix");
        assert!(f.head.is_none());
        assert!(f.versions.is_empty());
        assert!(!f.has_more);
        assert!(f.included.is_empty());
    }

    /// `fetch` after a commit returns the version + its trie root in
    /// `included`. Probes the populated envelope path.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_after_commit_returns_version_and_trie() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/fetch-after-commit/", pid);

        let data = entity_ecf::to_ecf(&entity_ecf::text("hi"));
        ctx.store()
            .put(&format!("{}n", prefix), Entity::new("app/note", data).unwrap())
            .unwrap();
        let c = ctx
            .revision()
            .commit(prefix.clone())
            .await
            .expect("commit");

        let f = ctx
            .revision()
            .fetch(prefix, None, None)
            .await
            .expect("fetch after commit");
        assert_eq!(f.head, Some(c.version));
        assert_eq!(f.versions, vec![c.version]);
        assert!(!f.has_more);
        // Version + trie root entities must both be present.
        assert!(f.included.contains_key(&c.version), "version entity included");
        assert!(f.included.contains_key(&c.root), "trie root entity included");
    }

    /// `fetch_entities` on a prefix with no HEAD returns 404
    /// `no_head`. Verifies the params shape (snapshot, hashes) is
    /// threaded correctly through the wire.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_entities_no_head_returns_404() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/never-fetched-entities/", pid);
        let snapshot = Hash::from_bytes(&[0x00u8; 33]).unwrap();
        let r = ctx
            .revision()
            .fetch_entities(prefix, snapshot, vec![])
            .await;
        match r {
            Err(SdkError::NotFound { status: 404, .. }) => {}
            other => panic!("expected 404 no_head, got {:?}", other),
        }
    }

    /// `fetch_entities` against a committed snapshot's trie root
    /// resolves the trie root itself when included in the request.
    /// Verifies the envelope decode + found/missing partitioning.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_entities_after_commit_returns_root() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/fetch-entities-ok/", pid);

        let data = entity_ecf::to_ecf(&entity_ecf::text("leaf"));
        ctx.store()
            .put(&format!("{}n", prefix), Entity::new("app/note", data).unwrap())
            .unwrap();
        let c = ctx
            .revision()
            .commit(prefix.clone())
            .await
            .expect("commit");

        let r = ctx
            .revision()
            .fetch_entities(prefix, c.root, vec![c.root])
            .await
            .expect("fetch_entities should succeed");
        assert_eq!(r.found, vec![c.root]);
        assert!(r.missing.is_empty());
        assert!(r.included.contains_key(&c.root));
    }

    /// `config_set` lands a config under a fresh name + reports
    /// `config_path` and `config_hash`. No tracking-config sidecar is
    /// involved since `auto_version: false`.
    #[tokio::test(flavor = "current_thread")]
    async fn config_set_lands_without_auto_version() {
        let ctx = make_ctx();
        let pid = ctx.peer_id().to_string();
        let prefix = format!("/{}/cfg-target/", pid);

        let cfg = RevisionConfigInput {
            prefix: prefix.clone(),
            auto_version: false,
            merge_order: None,
            oscillation_depth: None,
            exclude: vec![],
            exclude_types: vec![],
            checkout_under_auto_version: None,
        };

        let r = ctx
            .revision()
            .config_set("test-cfg", cfg, None)
            .await
            .expect("config_set should land");
        // Path shape is /{pid}/system/revision/{prefix_hash}/config —
        // the {prefix_hash} segment sits between revision/ and /config.
        assert!(r.config_path.starts_with(&format!("/{}/system/revision/", pid)));
        assert!(r.config_path.ends_with("/config"));
        assert!(r.config_hash.is_some());
        assert!(r.previous_hash.is_none(), "fresh write — no previous");
        assert!(r.tracking_config_path.is_none(), "auto_version=false → no sidecar");
    }

    /// `merge_config_set` rejects `deletion_resolution: lww` per
    /// §2.3. Verifies the wrapper threads the deletion_resolution
    /// field through encode_merge_config correctly.
    #[tokio::test(flavor = "current_thread")]
    async fn merge_config_set_rejects_lww() {
        let ctx = make_ctx();
        let r = ctx
            .revision()
            .merge_config_set(
                "path",
                "test-mc",
                MergeConfigInput {
                    pattern: "*".to_string(),
                    strategy: Some("three-way".to_string()),
                    deletion_resolution: Some("lww".to_string()),
                },
                None,
            )
            .await;
        match r {
            Err(SdkError::BadRequest { status: 400, .. }) => {}
            other => panic!("expected 400 invalid_strategy, got {:?}", other),
        }
    }

    /// `merge_config_set` + `merge_config_delete` round-trip. Verifies
    /// both encode_merge_config (set path) + the delete params shape +
    /// idempotency on re-set ("no_change").
    #[tokio::test(flavor = "current_thread")]
    async fn merge_config_set_then_delete_round_trip() {
        let ctx = make_ctx();
        let r = ctx
            .revision()
            .merge_config_set(
                "path",
                "round-trip",
                MergeConfigInput {
                    pattern: "*".to_string(),
                    strategy: Some("three-way".to_string()),
                    deletion_resolution: Some("preserve-on-conflict".to_string()),
                },
                None,
            )
            .await
            .expect("first set");
        assert_eq!(r.status, "set");
        let hash = r.hash.expect("set produces hash");
        assert!(r.path.contains("system/revision/config/merge/path/round-trip"));

        // Re-issuing the same content should report no_change.
        let r2 = ctx
            .revision()
            .merge_config_set(
                "path",
                "round-trip",
                MergeConfigInput {
                    pattern: "*".to_string(),
                    strategy: Some("three-way".to_string()),
                    deletion_resolution: Some("preserve-on-conflict".to_string()),
                },
                None,
            )
            .await
            .expect("idempotent re-set");
        assert_eq!(r2.status, "no_change");
        assert_eq!(r2.hash, Some(hash));

        let d = ctx
            .revision()
            .merge_config_delete("path", "round-trip", None)
            .await
            .expect("delete");
        assert_eq!(d.status, "deleted");
        assert!(d.hash.is_none());
    }
}
