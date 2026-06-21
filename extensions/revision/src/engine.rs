//! Revision engine — per-write auto-versioning (SyncTreeHook).
//!
//! Implements PROPOSAL-REVISION-AUTO-VERSION-FIX §6.1 as a synchronous emit
//! pathway consumer registered at SYSTEM-COMPOSITION §2.2 position 7, after
//! the structural-summaries root tracker (position 6) and before subscription
//! (position 8).
//!
//! For each tree write that matches a tracked prefix:
//!   1. Reads the tracked root from `system/tree/root/{canonical P}`.
//!   2. If `current_head.data.root == tracked_root`, dedups (no-op).
//!   3. Otherwise creates a `system/revision/entry` with
//!      `{root: tracked_root, parents: [current_head]}` and advances head.
//!   4. Advances the active-branch pointer when set.
//!
//! If auto-version is enabled for a prefix but the tracking-config / tracked
//! root binding is absent, the per-write invariant (§3 item 1) cannot be
//! satisfied: the error is logged (see §6.1 "Internal failure handling" /
//! §6D.5). Cascade-halt is not available through the current SyncTreeHook
//! interface — tracked as an implementation gap.

use std::sync::{Arc, RwLock};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{
    ChangeType, ContentStore, ExecutionContext, LocationIndex, SyncTreeHook, TreeChangeEvent,
};

use crate::dag::{build_revision_entry, decode_revision_entry, RevisionEntryData};
use entity_tree::trie;

// ---------------------------------------------------------------------------
// RevisionEngine — auto-version SyncTreeHook (spec position 7)
// ---------------------------------------------------------------------------

pub struct RevisionEngine {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id_str: String,
    /// Pre-computed `/{peer_id}/system/revision/` prefix for reentrancy guard
    /// and config listing (hash-addressed subtrees live under this prefix).
    revision_path_prefix: String,
    /// Pre-computed `/{peer_id}/system/tree/root/` for tracked-root lookups.
    root_path_prefix: String,
    /// Cached auto-version configs. Populated lazily from `None`. Invalidated
    /// when an event arrives at any `{revision_prefix}{66hex}/config` path so
    /// the hot path doesn't scan + decode the revision subtree per put.
    cached_configs: RwLock<Option<Vec<RevisionConfig>>>,
}

impl RevisionEngine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id_str: String,
    ) -> Self {
        let revision_path_prefix =
            format!("/{}/system/revision/", &local_peer_id_str);
        let root_path_prefix =
            format!("/{}/system/tree/root/", &local_peer_id_str);
        Self {
            content_store,
            location_index,
            local_peer_id_str,
            revision_path_prefix,
            root_path_prefix,
            cached_configs: RwLock::new(None),
        }
    }

    fn invalidate_config_cache(&self) {
        *self.cached_configs.write().unwrap() = None;
    }

    /// Storage path for the tracked root of a given canonical prefix
    /// (EXTENSION-TREE §3.4.1 path-substitution rule, §6B Amendment 1).
    fn tracked_root_path(&self, canonical: &str) -> String {
        if canonical.is_empty() {
            // Universal tree canonical form.
            format!("/{}/system/tree/root", self.local_peer_id_str)
        } else {
            format!("{}{}", self.root_path_prefix, canonical)
        }
    }

    /// Match a bare event path (relative to peer) against one config's prefix
    /// and exclude list. Returns true if auto-version should fire for this
    /// event under this config.
    fn config_matches(&self, event_bare_path: &str, config: &RevisionConfig) -> bool {
        let canonical = canonicalize_prefix(&config.prefix);
        let relative = if canonical.is_empty() {
            event_bare_path
        } else if let Some(r) = event_bare_path.strip_prefix(&format!("{}/", canonical)) {
            r
        } else if event_bare_path == canonical {
            ""
        } else {
            return false;
        };

        // Reentrancy: required excludes for universal-tree configs are
        // validated at coordination time (engine::validate_revision_config).
        // Here we only filter per the config's declared excludes.
        for pat in &config.exclude {
            if exclude_pattern_matches(pat, relative) {
                return false;
            }
        }
        true
    }

    /// Load + decode every auto-version-enabled config from the location index.
    /// Used by `cached_auto_version_configs` on cache miss and by the bootstrap
    /// path; not called per put.
    fn load_auto_version_configs(&self) -> Vec<RevisionConfig> {
        let mut result = Vec::new();
        let entries = self.location_index.list(&self.revision_path_prefix);
        for entry in entries {
            if !is_prefix_config_path(&entry.path, &self.revision_path_prefix) {
                continue;
            }
            let Some(entity) = self.content_store.get(&entry.hash) else {
                continue;
            };
            if entity.entity_type != "system/revision/config" {
                continue;
            }
            let Some(config) = decode_revision_config(&entity.data) else {
                continue;
            };
            if !config.auto_version {
                continue;
            }
            result.push(config);
        }
        result
    }

    /// Read-through cache for auto-version configs.
    fn cached_auto_version_configs(&self) -> Vec<RevisionConfig> {
        if let Some(ref cached) = *self.cached_configs.read().unwrap() {
            return cached.clone();
        }
        let loaded = self.load_auto_version_configs();
        *self.cached_configs.write().unwrap() = Some(loaded.clone());
        loaded
    }

    /// Collect configs whose `auto_version` is true and whose prefix + excludes
    /// match the event. Reads from the cached config list (refreshed on writes
    /// under the revision prefix-config subtree).
    fn matching_configs(&self, bare_path: &str) -> Vec<RevisionConfig> {
        self.cached_auto_version_configs()
            .into_iter()
            .filter(|c| self.config_matches(bare_path, c))
            .collect()
    }

    /// Execute the per-write auto-version algorithm for one config
    /// (PROPOSAL-REVISION-AUTO-VERSION-FIX §6.1).
    fn auto_version_once(
        &self,
        config: &RevisionConfig,
        ctx: &ExecutionContext,
    ) -> Result<(), String> {
        let canonical = canonicalize_prefix(&config.prefix);
        let tracked_root_path = self.tracked_root_path(&canonical);

        // §6.1 precondition: tracked root must be populated. If absent, the
        // tracking-config coordination invariant is violated (§6D.5 MUST).
        let tracked_root = self.location_index.get(&tracked_root_path).ok_or_else(|| {
            format!(
                "auto-version: tracking-config missing or disabled for prefix {:?} \
                 (no binding at {})",
                config.prefix, tracked_root_path
            )
        })?;

        // Resolve prefix to absolute form, then compute the hash-addressed
        // subtree key (EXTENSION-REVISION v3.0 §3.1).
        let abs_prefix = crate::resolve_prefix(&config.prefix, &self.local_peer_id_str);
        let ph = crate::prefix_hash(&abs_prefix);

        let head_path = crate::rev_head_path(&self.local_peer_id_str, &ph);
        let current_head = self.location_index.get(&head_path);

        // Dedup: if current head already records this root, nothing to do.
        if let Some(h) = current_head {
            if let Some(entry) = self
                .content_store
                .get(&h)
                .and_then(|e| decode_revision_entry(&e))
            {
                if entry.root == tracked_root {
                    return Ok(());
                }
            }
        }

        // Build and store the new revision entry.
        let mut parents: Vec<Hash> = current_head.into_iter().collect();
        trie::sorted_parents(&mut parents);
        let entry = build_revision_entry(&RevisionEntryData {
            root: tracked_root,
            parents,
        })?;
        let entry_hash = self.content_store.put(entry).map_err(|e| e.to_string())?;

        // Advance head. Per spec §6.1 "Contention handling", conformant
        // mechanisms are CAS+retry or single-writer-per-prefix serialization.
        // SyncTreeHooks fire synchronously within a single cascade thread;
        // cross-thread contention on this path is handled by the
        // NotifyingLocationIndex cascade discipline. A plain set() is
        // conformant under that serialization property.
        let _cascade = self.location_index
            .set_with_context(&head_path, entry_hash, ctx.clone());

        // Advance active-branch pointer when set (§6.1 algorithm step 4).
        let ab_path = crate::rev_active_branch_path(&self.local_peer_id_str, &ph);
        if let Some(ab_hash) = self.location_index.get(&ab_path) {
            if let Some(ab_entity) = self.content_store.get(&ab_hash) {
                if let Some(name) = decode_active_branch_name(&ab_entity) {
                    let branch_path = crate::rev_branch_path(
                        &self.local_peer_id_str,
                        &ph,
                        &name,
                    );
                    let _cascade = self.location_index
                        .set_with_context(&branch_path, entry_hash, ctx.clone());
                }
            }
        }

        Ok(())
    }
}

impl SyncTreeHook for RevisionEngine {
    fn on_tree_change(&self, event: &TreeChangeEvent, ctx: &mut ExecutionContext)
        -> Result<(), entity_store::CascadeHalt>
    {
        if event.path.starts_with(&self.revision_path_prefix) {
            // Writes under our own subtree don't trigger auto-version, but a
            // write to a `{revision_prefix}{66hex}/config` entry must
            // invalidate the cached config view so the next put sees fresh
            // configs.
            if is_prefix_config_path(&event.path, &self.revision_path_prefix) {
                self.invalidate_config_cache();
            }
            return Ok(());
        }

        let bare_path = match event
            .path
            .strip_prefix(&format!("/{}/", self.local_peer_id_str))
        {
            Some(s) => s,
            None => return Ok(()),
        };

        let configs = self.matching_configs(bare_path);
        if configs.is_empty() {
            return Ok(());
        }

        for config in configs {
            match self.auto_version_once(&config, ctx) {
                Ok(()) => tracing::debug!(
                    prefix = %config.prefix,
                    path = %event.path,
                    "revision: auto-version fired"
                ),
                Err(e) => {
                    tracing::error!(
                        prefix = %config.prefix,
                        path = %event.path,
                        error = %e,
                        "revision: auto-version failed — halting cascade"
                    );
                    return Err(entity_store::CascadeHalt {
                        consumer_name: self.name().to_string(),
                        error_code: 500,
                        error_message: format!("auto-version invariant violation: {}", e),
                        is_error: false,
                    });
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "revision/auto-version"
    }

    fn handler_pattern(&self) -> &str {
        "system/revision"
    }
}

/// Match an exclude pattern (glob-style, with `**` suffix supported) against
/// a relative path. Minimal matcher — exact and prefix forms only.
pub(crate) fn exclude_pattern_matches(pattern: &str, relative: &str) -> bool {
    let pat = pattern.trim_start_matches('/');
    // Strip trailing /** or /*
    let stripped = pat
        .strip_suffix("/**")
        .or_else(|| pat.strip_suffix("/*"))
        .unwrap_or(pat);
    if stripped == "**" || stripped.is_empty() {
        return true;
    }
    if pat.ends_with("**") || pat.ends_with("/*") {
        relative == stripped || relative.starts_with(&format!("{}/", stripped))
    } else {
        // Literal match (or literal-prefix fallback for patterns without **).
        relative == stripped || relative.starts_with(&format!("{}/", stripped))
    }
}

/// Test whether `path` is a hash-addressed prefix config entry under
/// `revision_prefix` (= `/{pid}/system/revision/`). The expected shape is
/// `{revision_prefix}{66hex}/config`.
fn is_prefix_config_path(path: &str, revision_prefix: &str) -> bool {
    let rest = match path.strip_prefix(revision_prefix) {
        Some(r) => r,
        None => return false,
    };
    // rest should be "{66hex}/config" → 66 + 1 + 6 = 73 chars
    if rest.len() != 66 + "/config".len() {
        return false;
    }
    let (hash_part, suffix) = rest.split_at(66);
    suffix == "/config" && hash_part.chars().all(|c| c.is_ascii_hexdigit())
}

fn decode_active_branch_name(entity: &Entity) -> Option<String> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("name") {
            return v.as_text().map(|s| s.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Config decoding
// ---------------------------------------------------------------------------

/// Default value for `merge_order` when unset — required for p2p convergence
/// across peers without coordination (PROPOSAL-REVISION-AUTO-VERSION-FIX §6D.1).
pub const DEFAULT_MERGE_ORDER: &str = "deterministic";

/// Default value for `checkout_under_auto_version` when unset
/// (PROPOSAL-REVISION-AUTO-VERSION-FIX §6A.4).
pub const DEFAULT_CHECKOUT_POLICY: &str = "warn";

/// Paths whose writes MUST be excluded from universal-tree auto-version to
/// avoid reentrancy cascades (PROPOSAL-REVISION-AUTO-VERSION-FIX §4 Reentrancy
/// + §6D.4). Each entry is a canonical-prefix form (no leading or trailing
///   slash) matched against a config's canonical prefix.
pub const REQUIRED_EXCLUDES: &[&str] = &[
    "system/revision",
    "system/tree/root",
    "system/tree/tracking-config",
    "system/history",
    "system/clock",
];

#[derive(Clone)]
pub struct RevisionConfig {
    pub prefix: String,
    pub auto_version: bool,
    pub merge_order: String,
    pub oscillation_depth: Option<u64>,
    pub exclude: Vec<String>,
    pub exclude_types: Vec<String>,
    pub checkout_under_auto_version: String,
}

pub fn decode_revision_config(data: &[u8]) -> Option<RevisionConfig> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;

    let mut prefix = None;
    let mut auto_version = false;
    let mut merge_order: Option<String> = None;
    let mut oscillation_depth = None;
    let mut exclude = Vec::new();
    let mut exclude_types = Vec::new();
    let mut checkout_policy: Option<String> = None;

    for (k, v) in map {
        match k.as_text()? {
            "prefix" => {
                prefix = v.as_text().map(|s| s.to_string());
            }
            "auto_version" => {
                auto_version = v.as_bool().unwrap_or(false);
            }
            "merge_order" => {
                merge_order = v.as_text().map(|s| s.to_string());
            }
            "oscillation_depth" => {
                oscillation_depth = v.as_integer().map(|i| i128::from(i) as u64);
            }
            "exclude" => {
                if let Some(arr) = v.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_text() {
                            exclude.push(s.to_string());
                        }
                    }
                }
            }
            "exclude_types" => {
                if let Some(arr) = v.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_text() {
                            exclude_types.push(s.to_string());
                        }
                    }
                }
            }
            "checkout_under_auto_version" => {
                checkout_policy = v.as_text().map(|s| s.to_string());
            }
            _ => {}
        }
    }

    Some(RevisionConfig {
        prefix: prefix?,
        auto_version,
        merge_order: merge_order.unwrap_or_else(|| DEFAULT_MERGE_ORDER.to_string()),
        oscillation_depth,
        exclude,
        exclude_types,
        checkout_under_auto_version: checkout_policy
            .unwrap_or_else(|| DEFAULT_CHECKOUT_POLICY.to_string()),
    })
}

/// Strip leading and trailing `/` from a prefix, yielding its canonical form.
/// `"/"` and `""` both collapse to `""` (the universal-tree canonical form).
/// Used for both storage-path substitution (EXTENSION-TREE §3.4.1) and
/// exclude-rule matching.
pub fn canonicalize_prefix(prefix: &str) -> String {
    prefix.trim_matches('/').to_string()
}

/// Validate a revision config against the PROPOSAL-REVISION-AUTO-VERSION-FIX
/// normative rules. Returns `Err` describing the first violation found.
///
/// Currently enforces:
/// - §6D.4 — when `auto_version: true` and the prefix encompasses a required-
///   exclude path, that path MUST appear (or be covered by) the `exclude` list.
/// - checkout policy and merge_order values are validated against the
///   enumerated options.
pub fn validate_revision_config(config: &RevisionConfig) -> Result<(), ConfigValidationError> {
    if config.prefix.is_empty() {
        return Err(ConfigValidationError {
            code: "config/invalid-prefix".into(),
            message: "prefix must not be empty".into(),
            status: 400,
        });
    }

    match config.merge_order.as_str() {
        "deterministic" | "caller-perspective" => {}
        other => {
            return Err(ConfigValidationError {
                code: "config/invalid-merge-order".into(),
                message: format!(
                    "merge_order {:?}: must be \"deterministic\" or \"caller-perspective\"",
                    other
                ),
                status: 400,
            });
        }
    }

    if let Some(depth) = config.oscillation_depth {
        if depth < 2 {
            return Err(ConfigValidationError {
                code: "config/oscillation-depth-below-minimum".into(),
                message: format!("oscillation_depth {} is below minimum 2", depth),
                status: 400,
            });
        }
    }

    match config.checkout_under_auto_version.as_str() {
        "allow" | "warn" | "deny" => {}
        other => {
            return Err(ConfigValidationError {
                code: "config/invalid-checkout-policy".into(),
                message: format!(
                    "checkout_under_auto_version {:?}: must be \"allow\", \"warn\", or \"deny\"",
                    other
                ),
                status: 400,
            });
        }
    }

    if !config.auto_version {
        return Ok(());
    }

    let canonical = canonicalize_prefix(&config.prefix);
    for required in REQUIRED_EXCLUDES {
        if !prefix_encompasses(&canonical, required) {
            continue;
        }
        if !exclude_list_covers(&config.exclude, &canonical, required) {
            return Err(ConfigValidationError {
                code: "config/missing-required-exclude".into(),
                message: format!(
                    "auto_version enabled on prefix {:?} encompasses {:?}; \
                     add exclude pattern (e.g., {:?})",
                    config.prefix,
                    required,
                    default_exclude_pattern(&canonical, required),
                ),
                status: 400,
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ConfigValidationError {
    pub code: String,
    pub message: String,
    pub status: u32,
}

/// Does `canonical_prefix` (canonical form, no slashes) encompass `target`
/// (canonical form)? Empty prefix encompasses everything; otherwise `target`
/// must equal `canonical_prefix` or start with `canonical_prefix/`.
fn prefix_encompasses(canonical_prefix: &str, target: &str) -> bool {
    if canonical_prefix.is_empty() {
        return true;
    }
    target == canonical_prefix
        || target.starts_with(&format!("{}/", canonical_prefix))
}

/// Does the exclude list contain a pattern that covers `target` (canonical
/// form) relative to `canonical_prefix`? Patterns are matched as the exclude
/// would be applied in `find_auto_version_prefixes` — i.e., a pattern that is
/// a path prefix of the required-exclude path (with or without a `**` suffix)
/// counts as covering it.
fn exclude_list_covers(excludes: &[String], canonical_prefix: &str, target: &str) -> bool {
    let target_relative = if canonical_prefix.is_empty() {
        target.to_string()
    } else if target == canonical_prefix {
        String::new()
    } else {
        target
            .strip_prefix(&format!("{}/", canonical_prefix))
            .unwrap_or(target)
            .to_string()
    };

    for raw in excludes {
        let pat = raw.trim_matches('/').trim_end_matches("**").trim_end_matches('/');
        if pat.is_empty() {
            return true;
        }
        if target_relative == pat
            || target_relative.starts_with(&format!("{}/", pat))
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// ConfigCoordinationHook
// ---------------------------------------------------------------------------

/// SyncTreeHook that coordinates `system/tree/tracking-config` state with
/// `system/revision/config/*` writes (filtered by entity type).
///
/// When a revision config is written with `auto_version: true`, ensures a
/// `system/tree/tracking-config` entity exists for the prefix with
/// `enabled: true`. When the revision config is removed or `auto_version`
/// flips to `false`, disables the matching tracking-config entity.
///
/// This is the config-write-time side of the coordination specified in
/// PROPOSAL-REVISION-AUTO-VERSION-FIX §4 "Trie root tracking coordination":
/// a valid tracking-config MUST exist whenever auto-version is enabled, and
/// the revision extension owns enforcing that invariant. The hook fires
/// inline during the same tree write that produced the revision config,
/// so the two entities stay in sync within a single emit cascade.
///
/// Validation: configs that fail `validate_revision_config` are logged and
/// skipped. Write-time rejection of such configs (spec §6D.4) is not yet
/// plumbed at the tree-write boundary; the runtime emit-time error (§6D.5)
/// will be added with the auto-version hook in a later stage.
pub struct ConfigCoordinationHook {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    /// Pre-computed `/{peer_id}/system/revision/` for detecting config events
    /// at `/{pid}/system/revision/{66hex}/config`.
    revision_prefix: String,
    tracking_path_prefix: String,
}

impl ConfigCoordinationHook {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let revision_prefix =
            format!("/{}/system/revision/", &local_peer_id);
        let tracking_path_prefix =
            format!("/{}/system/tree/tracking-config/", &local_peer_id);
        Self {
            content_store,
            location_index,
            revision_prefix,
            tracking_path_prefix,
        }
    }

    /// Compute the tracking-config tree path for a canonical prefix
    /// (no leading/trailing slashes). Universal prefix (empty canonical) is
    /// stored at `.../tracking-config/` via a sentinel segment to avoid the
    /// empty-trailing-segment ambiguity.
    fn tracking_path(&self, canonical: &str) -> String {
        if canonical.is_empty() {
            // Universal tree — represent with a reserved "root" segment so
            // the path has no trailing slash.
            format!("{}root", self.tracking_path_prefix)
        } else {
            format!("{}{}", self.tracking_path_prefix, canonical)
        }
    }

    fn build_tracking_config_entity(canonical: &str, enabled: bool) -> Option<Entity> {
        build_tracking_config_entity(canonical, enabled)
    }

    fn write_tracking_config(
        &self,
        canonical: &str,
        enabled: bool,
        ctx: &ExecutionContext,
    ) {
        let Some(entity) = Self::build_tracking_config_entity(canonical, enabled) else {
            tracing::error!(canonical = %canonical, "failed to build tracking-config entity");
            return;
        };
        let hash = match self.content_store.put(entity) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(error = %e, "tracking-config content_store.put failed");
                return;
            }
        };
        let path = self.tracking_path(canonical);
        let _cascade = self.location_index
            .set_with_context(&path, hash, ctx.clone());
        tracing::debug!(
            path = %path,
            enabled,
            "revision: tracking-config coordinated"
        );
    }

    fn coordinate_from_config(&self, config: &RevisionConfig, ctx: &ExecutionContext) {
        if let Err(e) = validate_revision_config(config) {
            tracing::error!(
                prefix = %config.prefix,
                error = %e.message,
                "revision: invalid config; skipping tracking-config coordination"
            );
            return;
        }
        let canonical = canonicalize_prefix(&config.prefix);
        self.write_tracking_config(&canonical, config.auto_version, ctx);
    }

    fn decode_config_at(&self, hash: &entity_hash::Hash) -> Option<RevisionConfig> {
        let entity = self.content_store.get(hash)?;
        // Only top-level config entities; skip sub-config types like
        // system/revision/config/merge/** entries that share the path tree.
        if entity.entity_type != "system/revision/config" {
            return None;
        }
        decode_revision_config(&entity.data)
    }
}

impl SyncTreeHook for ConfigCoordinationHook {
    fn on_tree_change(&self, event: &TreeChangeEvent, ctx: &mut ExecutionContext)
        -> Result<(), entity_store::CascadeHalt>
    {
        if !is_prefix_config_path(&event.path, &self.revision_prefix) {
            return Ok(());
        }

        match event.change_type {
            ChangeType::Created | ChangeType::Modified => {
                if let Some(config) = self.decode_config_at(&event.hash) {
                    if let Err(e) = validate_revision_config(&config) {
                        tracing::error!(
                            prefix = %config.prefix,
                            error = %e.message,
                            "revision: invalid config written directly — halting cascade"
                        );
                        return Err(entity_store::CascadeHalt {
                            consumer_name: self.name().to_string(),
                            error_code: e.status,
                            error_message: format!("{}: {}", e.code, e.message),
                            is_error: false,
                        });
                    }
                    self.coordinate_from_config(&config, ctx);
                }
            }
            ChangeType::Deleted => {
                if let Some(prev) = event.previous_hash {
                    if let Some(config) = self.decode_config_at(&prev) {
                        let canonical = canonicalize_prefix(&config.prefix);
                        self.write_tracking_config(&canonical, false, ctx);
                    }
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "revision/config-coordination"
    }

    fn handler_pattern(&self) -> &str {
        "system/revision/config"
    }
}

pub fn build_tracking_config_entity(canonical: &str, enabled: bool) -> Option<Entity> {
    let prefix = tracking_prefix_field(canonical);
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("enabled"), entity_ecf::bool_val(enabled)),
        (entity_ecf::text("prefix"), entity_ecf::text(&prefix)),
    ]));
    Entity::new("system/tree/tracking-config", data).ok()
}

fn tracking_prefix_field(canonical: &str) -> String {
    if canonical.is_empty() {
        "/".to_string()
    } else {
        format!("{}/", canonical)
    }
}

pub fn tracking_config_path(local_peer_id: &str, canonical: &str) -> String {
    let prefix = format!("/{}/system/tree/tracking-config/", local_peer_id);
    if canonical.is_empty() {
        format!("{}root", prefix)
    } else {
        format!("{}{}", prefix, canonical)
    }
}

fn default_exclude_pattern(canonical_prefix: &str, target: &str) -> String {
    let rel = if canonical_prefix.is_empty() {
        target.to_string()
    } else if target == canonical_prefix {
        String::new()
    } else {
        target
            .strip_prefix(&format!("{}/", canonical_prefix))
            .unwrap_or(target)
            .to_string()
    };
    if rel.is_empty() {
        "**".to_string()
    } else {
        format!("{}/**", rel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_hash::Hash;
    use entity_store::{ChangeType, MemoryContentStore, MemoryLocationIndex};

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

    /// Compute the prefix hash for a bare prefix resolved against a peer ID.
    fn test_ph(peer_id: &str, prefix: &str) -> String {
        crate::prefix_hash(&crate::resolve_prefix(prefix, peer_id))
    }

    // ConfigCoordinationHook tests --------------------------------------

    fn make_config_entity(cfg: &RevisionConfig) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("auto_version"),
                entity_ecf::bool_val(cfg.auto_version),
            ),
            (
                entity_ecf::text("exclude"),
                entity_ecf::Value::Array(
                    cfg.exclude.iter().map(|s| entity_ecf::text(s)).collect(),
                ),
            ),
            (
                entity_ecf::text("merge_order"),
                entity_ecf::text(&cfg.merge_order),
            ),
            (entity_ecf::text("prefix"), entity_ecf::text(&cfg.prefix)),
        ]));
        Entity::new("system/revision/config", data).unwrap()
    }

    fn decode_tracking_config_entity(entity: &Entity) -> Option<(String, bool)> {
        assert_eq!(entity.entity_type, "system/tree/tracking-config");
        let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
        let map = val.as_map()?;
        let mut prefix = None;
        let mut enabled = None;
        for (k, v) in map {
            match k.as_text()? {
                "prefix" => prefix = v.as_text().map(|s| s.to_string()),
                "enabled" => enabled = v.as_bool(),
                _ => {}
            }
        }
        Some((prefix?, enabled.unwrap_or(false)))
    }

    #[test]
    fn coordination_creates_tracking_config_on_auto_version_enable() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(
            store.clone(),
            li.clone(),
            peer_id.clone(),
        );

        let cfg = base_config("project/", true);
        let cfg_entity = make_config_entity(&cfg);
        let cfg_hash = store.put(cfg_entity).unwrap();
        let ph = test_ph(&peer_id, "project/");

        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: cfg_hash,
            previous_hash: None,
            new_hash: Some(cfg_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        hook.on_tree_change(&event, &mut ctx);

        let tc_path = format!("/{}/system/tree/tracking-config/project", peer_id);
        let tc_hash = li.get(&tc_path).expect("tracking-config should be created");
        let tc_entity = store.get(&tc_hash).expect("tc entity");
        let (pfx, enabled) = decode_tracking_config_entity(&tc_entity).unwrap();
        assert_eq!(pfx, "project/");
        assert!(enabled);
    }

    #[test]
    fn coordination_disables_tracking_config_on_auto_version_false() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(
            store.clone(),
            li.clone(),
            peer_id.clone(),
        );

        let cfg = base_config("project/", false);
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        let ph = test_ph(&peer_id, "project/");
        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: cfg_hash,
            previous_hash: None,
            new_hash: Some(cfg_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        hook.on_tree_change(&event, &mut ExecutionContext::default());

        let tc_path = format!("/{}/system/tree/tracking-config/project", peer_id);
        let tc_hash = li.get(&tc_path).expect("tracking-config still created");
        let tc_entity = store.get(&tc_hash).unwrap();
        let (_, enabled) = decode_tracking_config_entity(&tc_entity).unwrap();
        assert!(!enabled);
    }

    #[test]
    fn coordination_disables_on_config_removal() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(
            store.clone(),
            li.clone(),
            peer_id.clone(),
        );

        let cfg = base_config("project/", true);
        let prev_hash = store.put(make_config_entity(&cfg)).unwrap();
        let ph = test_ph(&peer_id, "project/");

        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: Hash::zero(),
            previous_hash: Some(prev_hash),
            new_hash: None,
            change_type: ChangeType::Deleted,
            context: None,
        };
        hook.on_tree_change(&event, &mut ExecutionContext::default());

        let tc_path = format!("/{}/system/tree/tracking-config/project", peer_id);
        let tc_hash = li.get(&tc_path).expect("tc written on removal");
        let tc_entity = store.get(&tc_hash).unwrap();
        let (_, enabled) = decode_tracking_config_entity(&tc_entity).unwrap();
        assert!(!enabled);
    }

    #[test]
    fn coordination_skips_invalid_configs() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(
            store.clone(),
            li.clone(),
            peer_id.clone(),
        );

        // Universal prefix with auto_version:true but no excludes → invalid.
        let cfg = base_config("/", true);
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        let ph = test_ph(&peer_id, "/");
        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: cfg_hash,
            previous_hash: None,
            new_hash: Some(cfg_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        hook.on_tree_change(&event, &mut ExecutionContext::default());

        // No tracking-config was written.
        let tc_path = format!("/{}/system/tree/tracking-config/root", peer_id);
        assert!(li.get(&tc_path).is_none());
    }

    #[test]
    fn coordination_universal_prefix_uses_root_segment() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(
            store.clone(),
            li.clone(),
            peer_id.clone(),
        );

        let mut cfg = base_config("/", true);
        cfg.exclude = vec!["system/**".to_string()];
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        let ph = test_ph(&peer_id, "/");
        let event = TreeChangeEvent {
            path: crate::rev_config_path(&peer_id, &ph),
            hash: cfg_hash,
            previous_hash: None,
            new_hash: Some(cfg_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        hook.on_tree_change(&event, &mut ExecutionContext::default());

        let tc_path = format!("/{}/system/tree/tracking-config/root", peer_id);
        let tc_hash = li.get(&tc_path).expect("universal tracking-config");
        let tc_entity = store.get(&tc_hash).unwrap();
        let (pfx, enabled) = decode_tracking_config_entity(&tc_entity).unwrap();
        assert_eq!(pfx, "/");
        assert!(enabled);
    }

    #[test]
    fn coordination_ignores_unrelated_paths() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let hook = ConfigCoordinationHook::new(
            store.clone(),
            li.clone(),
            peer_id.clone(),
        );

        let event = TreeChangeEvent {
            path: format!("/{}/project/foo", peer_id),
            hash: Hash::zero(),
            previous_hash: None,
            new_hash: Some(Hash::zero()),
            change_type: ChangeType::Created,
            context: None,
        };
        hook.on_tree_change(&event, &mut ExecutionContext::default());

        assert!(li.list("/").is_empty());
    }

    // RevisionEngine tests -----------------------------------------------

    #[test]
    fn test_skips_system_revision_paths() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());
        let ph = test_ph(&peer_id, "data/");

        let event = TreeChangeEvent {
            path: format!("/{}/system/revision/{}/head", peer_id, ph),
            hash: Hash::zero(),
            previous_hash: None,
            new_hash: Some(Hash::zero()),
            change_type: ChangeType::Created,
            context: None,
        };
        engine.on_tree_change(&event, &mut ExecutionContext::default());

        // No version created
        assert!(li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .is_none());
    }

    fn base_config(prefix: &str, auto_version: bool) -> RevisionConfig {
        RevisionConfig {
            prefix: prefix.to_string(),
            auto_version,
            merge_order: DEFAULT_MERGE_ORDER.to_string(),
            oscillation_depth: None,
            exclude: Vec::new(),
            exclude_types: Vec::new(),
            checkout_under_auto_version: DEFAULT_CHECKOUT_POLICY.to_string(),
        }
    }

    #[test]
    fn canonicalize_prefix_forms() {
        assert_eq!(canonicalize_prefix("/"), "");
        assert_eq!(canonicalize_prefix(""), "");
        assert_eq!(canonicalize_prefix("project/"), "project");
        assert_eq!(canonicalize_prefix("/project/src/"), "project/src");
        assert_eq!(canonicalize_prefix("project/src"), "project/src");
    }

    #[test]
    fn default_merge_order_is_deterministic() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("prefix"),
            entity_ecf::Value::Text("project/".to_string()),
        )]));
        let cfg = decode_revision_config(&data).expect("decode");
        assert_eq!(cfg.merge_order, "deterministic");
        assert_eq!(cfg.checkout_under_auto_version, "warn");
    }

    #[test]
    fn explicit_merge_order_preserved() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("prefix"),
                entity_ecf::Value::Text("project/".to_string()),
            ),
            (
                entity_ecf::text("merge_order"),
                entity_ecf::Value::Text("caller-perspective".to_string()),
            ),
        ]));
        let cfg = decode_revision_config(&data).expect("decode");
        assert_eq!(cfg.merge_order, "caller-perspective");
    }

    #[test]
    fn validate_accepts_auto_version_off() {
        // auto_version off — encompassing excludes are not required.
        let cfg = base_config("/", false);
        validate_revision_config(&cfg).expect("valid");
    }

    #[test]
    fn validate_accepts_non_encompassing_prefix() {
        let cfg = base_config("project/", true);
        validate_revision_config(&cfg).expect("valid");
    }

    #[test]
    fn validate_rejects_universal_without_excludes() {
        let cfg = base_config("/", true);
        let err = validate_revision_config(&cfg).expect_err("should reject");
        assert!(err.message.contains("system/revision"), "err was: {}", err.message);
    }

    #[test]
    fn validate_accepts_universal_with_system_shorthand() {
        let mut cfg = base_config("/", true);
        cfg.exclude = vec!["system/**".to_string()];
        validate_revision_config(&cfg).expect("valid");
    }

    #[test]
    fn validate_accepts_universal_with_full_enumeration() {
        let mut cfg = base_config("/", true);
        cfg.exclude = REQUIRED_EXCLUDES.iter().map(|p| format!("{}/**", p)).collect();
        validate_revision_config(&cfg).expect("valid");
    }

    #[test]
    fn validate_rejects_partial_enumeration() {
        let mut cfg = base_config("/", true);
        // Missing system/history and system/clock.
        cfg.exclude = vec![
            "system/revision/**".to_string(),
            "system/tree/root/**".to_string(),
            "system/tree/tracking-config/**".to_string(),
        ];
        let err = validate_revision_config(&cfg).expect_err("should reject");
        assert!(err.message.contains("system/history"), "err was: {}", err.message);
    }

    #[test]
    fn validate_rejects_encompassing_system_prefix() {
        // prefix /system/ encompasses system/revision, system/history, etc.
        let cfg = base_config("system/", true);
        let err = validate_revision_config(&cfg).expect_err("should reject");
        assert!(err.code == "config/missing-required-exclude", "code was: {}", err.code);
    }

    #[test]
    fn validate_rejects_bogus_merge_order() {
        let mut cfg = base_config("project/", true);
        cfg.merge_order = "random".to_string();
        validate_revision_config(&cfg).expect_err("should reject");
    }

    #[test]
    fn validate_rejects_bogus_checkout_policy() {
        let mut cfg = base_config("project/", true);
        cfg.checkout_under_auto_version = "maybe".to_string();
        validate_revision_config(&cfg).expect_err("should reject");
    }

    #[test]
    fn validate_accepts_all_checkout_policies() {
        for policy in ["allow", "warn", "deny"] {
            let mut cfg = base_config("project/", true);
            cfg.checkout_under_auto_version = policy.to_string();
            validate_revision_config(&cfg).expect("valid");
        }
    }

    #[test]
    fn test_no_auto_version_without_config() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());
        let ph = test_ph(&peer_id, "data/");

        let event = TreeChangeEvent {
            path: "data/foo".to_string(),
            hash: Hash::zero(),
            previous_hash: None,
            new_hash: Some(Hash::zero()),
            change_type: ChangeType::Created,
            context: None,
        };
        engine.on_tree_change(&event, &mut ExecutionContext::default());

        // No config, no version created
        assert!(li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .is_none());
    }

    /// Install a revision config in the tree at its hash-addressed path.
    /// `/{peer}/system/revision/{prefix_hash}/config` where prefix_hash is
    /// derived from the resolved absolute prefix.
    fn install_config(
        store: &Arc<MemoryContentStore>,
        li: &Arc<MemoryLocationIndex>,
        peer_id: &str,
        _name: &str,
        cfg: &RevisionConfig,
    ) {
        let cfg_hash = store.put(make_config_entity(cfg)).unwrap();
        let ph = test_ph(peer_id, &cfg.prefix);
        li.set(
            &crate::rev_config_path(peer_id, &ph),
            cfg_hash,
        );
    }

    /// Seed the tracked-root binding that the root tracker would normally
    /// produce at position 6.
    fn seed_tracked_root(
        li: &Arc<MemoryLocationIndex>,
        peer_id: &str,
        canonical: &str,
        hash: Hash,
    ) {
        let path = if canonical.is_empty() {
            format!("/{}/system/tree/root", peer_id)
        } else {
            format!("/{}/system/tree/root/{}", peer_id, canonical)
        };
        li.set(&path, hash);
    }

    fn event_for(peer_id: &str, path: &str, hash: Hash) -> TreeChangeEvent {
        TreeChangeEvent {
            path: format!("/{}/{}", peer_id, path),
            hash,
            previous_hash: None,
            new_hash: Some(hash),
            change_type: ChangeType::Created,
            context: None,
        }
    }

    fn sample_hash(byte: u8) -> Hash {
        let mut digest = [0u8; 32];
        digest[0] = byte;
        Hash::new(0, digest)
    }

    #[test]
    fn auto_version_creates_entry_from_tracked_root() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        install_config(&store, &li, &peer_id, "main", &cfg);

        let root = sample_hash(0x42);
        seed_tracked_root(&li, &peer_id, "project", root);

        let evt = event_for(&peer_id, "project/file.txt", sample_hash(0x01));
        engine.on_tree_change(&evt, &mut ExecutionContext::default());

        let ph = test_ph(&peer_id, "project/");
        let head_hash = li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .expect("head set");
        let head_entity = store.get(&head_hash).unwrap();
        let entry = decode_revision_entry(&head_entity).unwrap();
        assert_eq!(entry.root, root);
        assert!(entry.parents.is_empty());
    }

    #[test]
    fn auto_version_dedups_when_root_unchanged() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        install_config(&store, &li, &peer_id, "main", &cfg);

        let root = sample_hash(0x42);
        seed_tracked_root(&li, &peer_id, "project", root);

        let ph = test_ph(&peer_id, "project/");
        let evt = event_for(&peer_id, "project/file.txt", sample_hash(0x01));
        engine.on_tree_change(&evt, &mut ExecutionContext::default());
        let first_head = li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .unwrap();

        // Same tracked root, another event — must dedup.
        engine.on_tree_change(&evt, &mut ExecutionContext::default());
        let second_head = li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .unwrap();
        assert_eq!(first_head, second_head);
    }

    #[test]
    fn auto_version_chains_on_root_change() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        install_config(&store, &li, &peer_id, "main", &cfg);

        let ph = test_ph(&peer_id, "project/");
        seed_tracked_root(&li, &peer_id, "project", sample_hash(0x01));
        let evt = event_for(&peer_id, "project/file.txt", sample_hash(0xaa));
        engine.on_tree_change(&evt, &mut ExecutionContext::default());
        let first_head = li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .unwrap();

        seed_tracked_root(&li, &peer_id, "project", sample_hash(0x02));
        engine.on_tree_change(&evt, &mut ExecutionContext::default());
        let second_head = li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .unwrap();

        assert_ne!(first_head, second_head);
        let entry = decode_revision_entry(&store.get(&second_head).unwrap()).unwrap();
        assert_eq!(entry.root, sample_hash(0x02));
        assert_eq!(entry.parents, vec![first_head]);
    }

    #[test]
    fn auto_version_errors_when_tracked_root_missing() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg = base_config("project/", true);
        install_config(&store, &li, &peer_id, "main", &cfg);

        // No seed — tracking-config invariant violated.
        let ph = test_ph(&peer_id, "project/");
        let evt = event_for(&peer_id, "project/file.txt", sample_hash(0x01));
        engine.on_tree_change(&evt, &mut ExecutionContext::default());

        assert!(li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .is_none());
    }

    #[test]
    fn auto_version_skips_own_path() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        // Config covers universal tree; reentrancy guard still excludes us.
        let mut cfg = base_config("/", true);
        cfg.exclude = vec!["system/**".to_string()];
        install_config(&store, &li, &peer_id, "universal", &cfg);
        seed_tracked_root(&li, &peer_id, "", sample_hash(0x11));

        let evt = event_for(
            &peer_id,
            "system/revision/head/something",
            sample_hash(0xff),
        );
        engine.on_tree_change(&evt, &mut ExecutionContext::default());

        // No head was advanced anywhere — own-path write is ignored.
        assert!(li.list("/").iter().all(|e| !e.path.ends_with("/head")));
    }

    #[test]
    fn auto_version_respects_exclude_patterns() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let mut cfg = base_config("project/", true);
        cfg.exclude = vec!["build/**".to_string()];
        install_config(&store, &li, &peer_id, "main", &cfg);
        seed_tracked_root(&li, &peer_id, "project", sample_hash(0x01));

        let ph = test_ph(&peer_id, "project/");
        let evt = event_for(&peer_id, "project/build/out.bin", sample_hash(0xbb));
        engine.on_tree_change(&evt, &mut ExecutionContext::default());

        assert!(li
            .get(&crate::rev_head_path(&peer_id, &ph))
            .is_none());
    }

    /// End-to-end: install both hooks on a NotifyingLocationIndex, write a
    /// revision config, then a tracked-prefix entity, and verify the config-
    /// coordination + auto-version cascade produces a version entry. The
    /// tracked-root step is hand-seeded here since the position-6 root
    /// tracker lives in `core/tree` (outside this crate).
    #[test]
    fn end_to_end_cascade_through_notifying_index() {
        use entity_store::NotifyingLocationIndex;

        let peer_id = test_peer_id();
        let inner = Arc::new(MemoryLocationIndex::new());
        let store = Arc::new(MemoryContentStore::new());
        let noop_broadcast: Arc<dyn Fn(TreeChangeEvent) + Send + Sync> =
            Arc::new(|_| {});
        let notifying =
            Arc::new(NotifyingLocationIndex::new(inner.clone(), noop_broadcast));

        let coord = Arc::new(ConfigCoordinationHook::new(
            store.clone(),
            notifying.clone(),
            peer_id.clone(),
        ));
        let engine = Arc::new(RevisionEngine::new(
            store.clone(),
            notifying.clone(),
            peer_id.clone(),
        ));
        notifying.register_hook(coord);
        notifying.register_hook(engine);

        let ph = test_ph(&peer_id, "project/");

        // Step 1: write a revision config through the notifying index. This
        // triggers the coord hook, which creates a tracking-config entity.
        let cfg = base_config("project/", true);
        let cfg_hash = store.put(make_config_entity(&cfg)).unwrap();
        entity_store::LocationIndex::set(
            notifying.as_ref(),
            &crate::rev_config_path(&peer_id, &ph),
            cfg_hash,
        );
        let tc_path = format!("/{}/system/tree/tracking-config/project", peer_id);
        assert!(
            inner.get(&tc_path).is_some(),
            "config-coordination hook must have written tracking-config"
        );

        // Step 2: simulate the position-6 root tracker producing a tracked
        // root for the prefix. In the real peer this binding is maintained
        // incrementally by `entity_tree::root_tracker::RootTrackerEngine`.
        let tracked_root = sample_hash(0x99);
        entity_store::LocationIndex::set(
            notifying.as_ref(),
            &format!("/{}/system/tree/root/project", peer_id),
            tracked_root,
        );

        // Step 3: a tree write under the tracked prefix. The auto-version
        // hook at position 7 reads the tracked root and creates an entry.
        entity_store::LocationIndex::set(
            notifying.as_ref(),
            &format!("/{}/project/file.txt", peer_id),
            sample_hash(0x01),
        );

        let head_hash = inner
            .get(&crate::rev_head_path(&peer_id, &ph))
            .expect("auto-version must have created an entry");
        let entry = decode_revision_entry(&store.get(&head_hash).unwrap()).unwrap();
        assert_eq!(entry.root, tracked_root);
        assert!(entry.parents.is_empty(), "first version has no parents");
    }

    #[test]
    fn auto_version_overlapping_prefixes_each_get_version() {
        let (store, li) = make_stores();
        let peer_id = test_peer_id();
        let engine = RevisionEngine::new(store.clone(), li.clone(), peer_id.clone());

        let cfg_outer = base_config("project/", true);
        install_config(&store, &li, &peer_id, "outer", &cfg_outer);
        let cfg_inner = base_config("project/src/", true);
        install_config(&store, &li, &peer_id, "inner", &cfg_inner);

        seed_tracked_root(&li, &peer_id, "project", sample_hash(0xaa));
        seed_tracked_root(&li, &peer_id, "project/src", sample_hash(0xbb));

        let ph_outer = test_ph(&peer_id, "project/");
        let ph_inner = test_ph(&peer_id, "project/src/");

        let evt = event_for(&peer_id, "project/src/file.rs", sample_hash(0x11));
        engine.on_tree_change(&evt, &mut ExecutionContext::default());

        let outer = li
            .get(&crate::rev_head_path(&peer_id, &ph_outer))
            .expect("outer head");
        let inner = li
            .get(&crate::rev_head_path(&peer_id, &ph_inner))
            .expect("inner head");
        assert_ne!(outer, inner);
        assert_eq!(
            decode_revision_entry(&store.get(&outer).unwrap()).unwrap().root,
            sample_hash(0xaa)
        );
        assert_eq!(
            decode_revision_entry(&store.get(&inner).unwrap()).unwrap().root,
            sample_hash(0xbb)
        );
    }
}
