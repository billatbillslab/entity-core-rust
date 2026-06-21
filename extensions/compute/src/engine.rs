use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{
    CascadeHalt, ContentStore, ExecutionContext, LocationIndex, SyncTreeHook, TreeChangeEvent,
};
use entity_ecf::ValueExt;

use crate::eval::{self, qualify_path, EvalContext};
use crate::types::*;
use crate::walker;

// ---------------------------------------------------------------------------
// DependencyIndex
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DependencyEntry {
    pub expression_uri: String,
    pub subgraph_path: String,
}

#[derive(Default)]
pub struct DependencyIndex {
    entries: RwLock<HashMap<String, Vec<DependencyEntry>>>,
}

impl DependencyIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, path: &str, entry: DependencyEntry) {
        let mut map = self.entries.write().unwrap();
        map.entry(path.to_string()).or_default().push(entry);
    }

    pub fn lookup(&self, path: &str) -> Vec<DependencyEntry> {
        let map = self.entries.read().unwrap();
        map.get(path).cloned().unwrap_or_default()
    }

    pub fn remove_subgraph(&self, subgraph_path: &str) {
        let mut map = self.entries.write().unwrap();
        for entries in map.values_mut() {
            entries.retain(|e| e.subgraph_path != subgraph_path);
        }
        map.retain(|_, v| !v.is_empty());
    }

    pub fn clear(&self) {
        let mut map = self.entries.write().unwrap();
        map.clear();
    }

    pub fn len(&self) -> usize {
        let map = self.entries.read().unwrap();
        map.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// ComputeEngine
// ---------------------------------------------------------------------------

pub struct ComputeEngine {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    #[allow(dead_code)]
    identity_hash: Hash,
    compute_path_prefix: String,
    pub dependency_index: Arc<DependencyIndex>,
}

impl ComputeEngine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        identity_hash: Hash,
    ) -> Self {
        let compute_path_prefix = format!("/{}/system/compute/", local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            identity_hash,
            compute_path_prefix,
            dependency_index: Arc::new(DependencyIndex::new()),
        }
    }

    /// Register dependencies for a subgraph (§7.1).
    pub fn register_subgraph_dependencies(
        &self,
        subgraph_path: &str,
        root_path: &str,
        expression: &Entity,
    ) {
        let included = HashMap::new();
        let dep_paths = walker::walk_tree_lookups(
            expression,
            self.content_store.as_ref(),
            &included,
            Some(root_path),
        );

        for path in dep_paths {
            let qualified = qualify_path(&path, &self.local_peer_id);
            self.dependency_index.add(
                &qualified,
                DependencyEntry {
                    expression_uri: root_path.to_string(),
                    subgraph_path: subgraph_path.to_string(),
                },
            );
        }
    }

    /// Rebuild the dependency index by scanning installed subgraphs (§7.1).
    pub fn rebuild_index(&self) {
        self.dependency_index.clear();
        let prefix = format!("/{}/system/compute/processes/", self.local_peer_id);
        let entries = self.location_index.list(&prefix);

        for entry in entries {
            let subgraph_entity = match self.content_store.get(&entry.hash) {
                Some(e) => e,
                None => continue,
            };

            if subgraph_entity.entity_type != TYPE_SUBGRAPH {
                continue;
            }

            let data = match decode_data(&subgraph_entity) {
                Some(d) => d,
                None => continue,
            };

            let status = data_str(&data, "status").unwrap_or_default();
            if status != "active" {
                continue;
            }

            let root_path = match data_str(&data, "root_expression_path") {
                Some(p) => p,
                None => continue,
            };

            let qualified_root = qualify_path(&root_path, &self.local_peer_id);
            let expr_hash = match self.location_index.get(&qualified_root) {
                Some(h) => h,
                None => continue,
            };

            let expression = match self.content_store.get(&expr_hash) {
                Some(e) => e,
                None => continue,
            };

            if !is_compute_expression(&expression) {
                continue;
            }

            let bare_subgraph = entry.path
                .strip_prefix(&format!("/{}/", self.local_peer_id))
                .unwrap_or(&entry.path)
                .to_string();

            self.register_subgraph_dependencies(&bare_subgraph, &root_path, &expression);
        }
    }

    fn re_evaluate(
        &self,
        entry: &DependencyEntry,
        ctx: &mut ExecutionContext,
    ) {
        let qualified_subgraph = qualify_path(&entry.subgraph_path, &self.local_peer_id);
        let subgraph_hash = match self.location_index.get(&qualified_subgraph) {
            Some(h) => h,
            None => {
                self.dependency_index.remove_subgraph(&entry.subgraph_path);
                return;
            }
        };

        let subgraph = match self.content_store.get(&subgraph_hash) {
            Some(e) => e,
            None => return,
        };

        if subgraph.entity_type != TYPE_SUBGRAPH {
            return;
        }

        let data = match decode_data(&subgraph) {
            Some(d) => d,
            None => return,
        };

        let root_path = match data_str(&data, "root_expression_path") {
            Some(p) => p,
            None => return,
        };

        let result_path = match data_str(&data, "result_path") {
            Some(p) => p,
            None => return,
        };

        // §7.2: Verify installation grant is still available and not expired
        let grant_hash = data_hash(&data, "installation_grant");
        let installation_grant = grant_hash.and_then(|h| self.content_store.get(&h));
        let grant_token = installation_grant.as_ref().and_then(|e| {
            entity_capability::CapabilityToken::from_entity(e).ok()
        });

        if let Some(ref token) = grant_token {
            if let Some(expires_at) = token.expires_at {
                let now = web_time::SystemTime::now()
                    .duration_since(web_time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if now > expires_at {
                    self.freeze_subgraph(
                        &entry.subgraph_path,
                        &result_path,
                        "installation_grant_invalid",
                        "Installation grant expired",
                        ctx,
                    );
                    return;
                }
            }
        } else if grant_hash.is_some() {
            // Grant hash recorded but entity not found or not decodable
            self.freeze_subgraph(
                &entry.subgraph_path,
                &result_path,
                "installation_grant_invalid",
                "Installation grant missing or invalid",
                ctx,
            );
            return;
        }

        let qualified_root = qualify_path(&root_path, &self.local_peer_id);
        let expr_hash = match self.location_index.get(&qualified_root) {
            Some(h) => h,
            None => {
                self.dependency_index.remove_subgraph(&entry.subgraph_path);
                return;
            }
        };

        let expression = match self.content_store.get(&expr_hash) {
            Some(e) => e,
            None => return,
        };

        // §7.4: Reactive budget bounded by installation grant constraints
        let mut budget = reactive_budget(grant_token.as_ref());

        // v3.7 D5: Load authorized data hashes from subgraph metadata
        let authorized_hashes = load_authorized_hashes(&data);

        let included = HashMap::new();
        let mut eval_ctx = EvalContext::new(
            self.content_store.as_ref(),
            self.location_index.as_ref(),
            &included,
            &self.local_peer_id,
        )
        .with_capability(grant_token.as_ref())
        .with_authorized_hashes(authorized_hashes)
        .with_subgraph_root(Some(root_path.clone()));

        let scope = crate::types::Scope::new();
        let result = eval::evaluate(&expression, &scope, &mut budget, &mut eval_ctx);

        // Handle evaluation errors — write to result_path but do NOT freeze
        // (budget_exhausted is transient, §7.3)
        if let ComputeValue::Error(ref err) = result {
            let error_entity = err.to_entity();
            let error_hash = self.content_store.put(error_entity).expect("store error");
            let qualified_result = qualify_path(&result_path, &self.local_peer_id);
            self.location_index.set_with_context(&qualified_result, error_hash, ctx.clone());
            return;
        }

        // Convergence check: compare result hash with existing
        let result_entity = result.to_result_entity(&expression.content_hash);
        let new_hash = result_entity.content_hash;

        let qualified_result = qualify_path(&result_path, &self.local_peer_id);
        let old_hash = self.location_index.get(&qualified_result);

        if old_hash == Some(new_hash) {
            return;
        }

        let stored_hash = self.content_store.put(result_entity).expect("store result");
        self.location_index.set_with_context(&qualified_result, stored_hash, ctx.clone());
    }

    fn freeze_subgraph(
        &self,
        subgraph_path: &str,
        result_path: &str,
        error_code: &str,
        error_message: &str,
        ctx: &mut ExecutionContext,
    ) {
        let error_data = entity_ecf::cbor_map! {
            "code" => entity_ecf::text(error_code),
            "message" => entity_ecf::text(error_message)
        };
        let error_entity = Entity::new(TYPE_ERROR, entity_ecf::to_ecf(&error_data))
            .expect("error entity");
        let error_hash = self.content_store.put(error_entity).expect("store error");

        let qualified_result = qualify_path(result_path, &self.local_peer_id);
        self.location_index.set_with_context(&qualified_result, error_hash, ctx.clone());

        // Update subgraph status to frozen
        let qualified_subgraph = qualify_path(subgraph_path, &self.local_peer_id);
        if let Some(sg_hash) = self.location_index.get(&qualified_subgraph) {
            if let Some(sg_entity) = self.content_store.get(&sg_hash) {
                if let Some(mut sg_data) = decode_data(&sg_entity) {
                    entity_ecf::map_insert(&mut sg_data, "status", entity_ecf::text("frozen"));
                    let new_data = entity_ecf::to_ecf(&sg_data);
                    if let Ok(updated) = Entity::new(TYPE_SUBGRAPH, new_data) {
                        let updated_hash = self.content_store.put(updated).expect("store frozen subgraph");
                        self.location_index.set(&qualified_subgraph, updated_hash);
                    }
                }
            }
        }
    }
}

/// Load authorized_data_hashes from subgraph metadata (v3.7 D5).
fn load_authorized_hashes(subgraph_data: &ciborium::Value) -> HashSet<Hash> {
    let mut set = HashSet::new();
    if let Some(arr) = subgraph_data.get("authorized_data_hashes").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(bytes) = item.as_bytes() {
                if let Ok(hash) = Hash::from_bytes(bytes) {
                    set.insert(hash);
                }
            }
        }
    }
    set
}

/// Build reactive budget bounded by installation grant constraints (§7.4).
fn reactive_budget(grant_token: Option<&entity_capability::CapabilityToken>) -> Budget {
    let token = match grant_token {
        Some(t) => t,
        None => return Budget::default_budget(),
    };

    // Look through grants for system/compute constraints
    for grant in &token.grants {
        if let Some(ref constraints) = grant.constraints {
            if let Some(compute) = constraints.get("system/compute") {
                let ops = compute
                    .get("max_compute_operations")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(PEER_DEFAULT_MAX_OPS);
                let depth = compute
                    .get("max_compute_depth")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(PEER_DEFAULT_MAX_DEPTH);
                return Budget::new(ops, depth);
            }
        }
    }

    Budget::default_budget()
}

// ---------------------------------------------------------------------------
// SyncTreeHook — position 5 (SYSTEM-COMPOSITION §2.2)
// ---------------------------------------------------------------------------

impl SyncTreeHook for ComputeEngine {
    fn on_tree_change(
        &self,
        event: &TreeChangeEvent,
        ctx: &mut ExecutionContext,
    ) -> Result<(), CascadeHalt> {
        // Self-guard: skip writes under system/compute/
        if event.path.starts_with(&self.compute_path_prefix) {
            return Ok(());
        }

        let entries = self.dependency_index.lookup(&event.path);
        if entries.is_empty() {
            return Ok(());
        }

        for entry in entries {
            // Load subgraph metadata to check status
            let qualified_subgraph = qualify_path(&entry.subgraph_path, &self.local_peer_id);
            let sg_hash = match self.location_index.get(&qualified_subgraph) {
                Some(h) => h,
                None => continue,
            };
            let sg_entity = match self.content_store.get(&sg_hash) {
                Some(e) => e,
                None => continue,
            };
            let sg_data = match decode_data(&sg_entity) {
                Some(d) => d,
                None => continue,
            };

            let status = data_str(&sg_data, "status").unwrap_or_default();
            if status == "frozen" {
                continue;
            }

            let result_path = match data_str(&sg_data, "result_path") {
                Some(p) => p,
                None => continue,
            };

            // Cascade depth check: >= 16 → freeze (§7.3)
            if ctx.cascade_depth >= CASCADE_DEPTH_COMPUTE_FREEZE {
                self.freeze_subgraph(
                    &entry.subgraph_path,
                    &result_path,
                    "cascade_limit",
                    "Cascade depth exceeded during reactive re-evaluation",
                    ctx,
                );
                continue;
            }

            self.re_evaluate(&entry, ctx);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "compute/reactive"
    }

    fn handler_pattern(&self) -> &str {
        "system/compute"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;
    use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};

    const TEST_PID: &str = "testpeer123456789012345678901234567890123456";

    fn make_literal_int(n: i64) -> Entity {
        let data = entity_ecf::cbor_map! {
            "value" => entity_ecf::integer(n)
        };
        Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
    }

    fn make_tree_lookup(path: &str) -> Entity {
        let data = entity_ecf::cbor_map! {
            "path" => entity_ecf::text(path)
        };
        Entity::new(TYPE_LOOKUP_TREE, entity_ecf::to_ecf(&data)).unwrap()
    }

    fn make_subgraph_metadata(root_path: &str, result_path: &str) -> Entity {
        let author = Hash::compute("test", b"author");
        let grant = Hash::compute("test", b"grant");
        let root_hash = Hash::compute("test", b"root");
        let data = entity_ecf::cbor_map! {
            "installation_grant" => Value::Bytes(grant.to_bytes().to_vec()),
            "installed_by" => Value::Bytes(author.to_bytes().to_vec()),
            "result_path" => entity_ecf::text(result_path),
            "root_expression" => Value::Bytes(root_hash.to_bytes().to_vec()),
            "root_expression_path" => entity_ecf::text(root_path),
            "status" => entity_ecf::text("active")
        };
        Entity::new(TYPE_SUBGRAPH, entity_ecf::to_ecf(&data)).unwrap()
    }

    #[test]
    fn test_dependency_index_add_lookup() {
        let index = DependencyIndex::new();
        index.add("app/data/x", DependencyEntry {
            expression_uri: "app/expr/1".into(),
            subgraph_path: "system/compute/processes/abc".into(),
        });

        let entries = index.lookup("app/data/x");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].expression_uri, "app/expr/1");
    }

    #[test]
    fn test_dependency_index_remove_subgraph() {
        let index = DependencyIndex::new();
        index.add("app/data/x", DependencyEntry {
            expression_uri: "app/expr/1".into(),
            subgraph_path: "system/compute/processes/abc".into(),
        });
        index.add("app/data/x", DependencyEntry {
            expression_uri: "app/expr/2".into(),
            subgraph_path: "system/compute/processes/def".into(),
        });

        index.remove_subgraph("system/compute/processes/abc");

        let entries = index.lookup("app/data/x");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].subgraph_path, "system/compute/processes/def");
    }

    #[test]
    fn test_register_subgraph_dependencies() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let identity_hash = Hash::compute("test", b"identity");

        let engine = ComputeEngine::new(cs.clone(), li.clone(), TEST_PID.to_string(), identity_hash);

        let lookup = make_tree_lookup("app/data/x");
        cs.put(lookup.clone()).unwrap();

        engine.register_subgraph_dependencies(
            "system/compute/processes/test1",
            "app/expr/1",
            &lookup,
        );

        // Index stores qualified paths — matching event.path format
        let qualified = format!("/{}/app/data/x", TEST_PID);
        let entries = engine.dependency_index.lookup(&qualified);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_self_guard() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let identity_hash = Hash::compute("test", b"identity");

        let engine = ComputeEngine::new(cs.clone(), li.clone(), TEST_PID.to_string(), identity_hash);

        let event = TreeChangeEvent {
            path: format!("/{}/system/compute/processes/abc", TEST_PID),
            hash: Hash::compute("test", b"x"),
            previous_hash: None,
            new_hash: Some(Hash::compute("test", b"x")),
            change_type: entity_store::ChangeType::Created,
            context: None,
        };

        let mut ctx = ExecutionContext::default();
        let result = engine.on_tree_change(&event, &mut ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reactive_re_evaluation() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let identity_hash = Hash::compute("test", b"identity");

        // Store a literal at app/data/x
        let lit = make_literal_int(42);
        let lit_h = cs.put(lit).unwrap();
        li.set(&format!("/{}/app/data/x", TEST_PID), lit_h);

        // Create a tree lookup expression for app/data/x
        let lookup = make_tree_lookup("app/data/x");
        let lookup_h = cs.put(lookup.clone()).unwrap();
        li.set(&format!("/{}/app/expr/1", TEST_PID), lookup_h);

        // Create subgraph metadata
        let metadata = make_subgraph_metadata("app/expr/1", "app/results/1");
        let meta_h = cs.put(metadata).unwrap();
        li.set(&format!("/{}/system/compute/processes/test1", TEST_PID), meta_h);

        let engine = ComputeEngine::new(cs.clone(), li.clone(), TEST_PID.to_string(), identity_hash);

        // Register dependency with qualified path (matching event.path format)
        engine.dependency_index.add(&format!("/{}/app/data/x", TEST_PID), DependencyEntry {
            expression_uri: "app/expr/1".into(),
            subgraph_path: "system/compute/processes/test1".into(),
        });

        // Trigger re-evaluation
        let event = TreeChangeEvent {
            path: format!("/{}/app/data/x", TEST_PID),
            hash: lit_h,
            previous_hash: None,
            new_hash: Some(lit_h),
            change_type: entity_store::ChangeType::Modified,
            context: None,
        };

        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx).unwrap();

        // Check that result was written
        let result_path = format!("/{}/app/results/1", TEST_PID);
        assert!(li.get(&result_path).is_some());
    }

    /// PROPOSAL-CROSS-IMPL-STANDARDIZATION-CATCHUP §1 regression — end-to-end
    /// bare-path → recompute. Locks in the invariant that
    /// `register_subgraph_dependencies` canonicalizes a bare lookup path
    /// (`app/data/x`) into the qualified form (`/peer/app/data/x`) at the
    /// dep-index entry, so a subsequent write at the canonical tree-write
    /// path matches and triggers recompute. Go found the verbatim-no-track
    /// shape pre-fix; this test prevents Rust from drifting back into it.
    #[test]
    fn test_bare_path_lookup_canonicalized_at_registration_fires_recompute() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let identity_hash = Hash::compute("test", b"identity");

        // Seed the dependency-target binding at the QUALIFIED path (where
        // tree-writes actually land per V7 §5.4).
        let lit = make_literal_int(42);
        let lit_h = cs.put(lit).unwrap();
        li.set(&format!("/{}/app/data/x", TEST_PID), lit_h);

        // Lookup expression carries a BARE path (`app/data/x`, relative
        // false/absent) — the case the proposal calls out.
        let lookup = make_tree_lookup("app/data/x");
        let lookup_h = cs.put(lookup.clone()).unwrap();
        li.set(&format!("/{}/app/expr/1", TEST_PID), lookup_h);

        let metadata = make_subgraph_metadata("app/expr/1", "app/results/1");
        let meta_h = cs.put(metadata).unwrap();
        li.set(&format!("/{}/system/compute/processes/test1", TEST_PID), meta_h);

        let engine = ComputeEngine::new(cs.clone(), li.clone(), TEST_PID.to_string(), identity_hash);

        // Register through the real path — walker emits the bare path,
        // engine.register_subgraph_dependencies canonicalizes at the index
        // entry. No manual `dependency_index.add` (which would mask the bug).
        engine.register_subgraph_dependencies(
            "system/compute/processes/test1",
            "app/expr/1",
            &lookup,
        );

        // The dep-index entry MUST be keyed by the qualified path —
        // otherwise the change event below would not match.
        let qualified = format!("/{}/app/data/x", TEST_PID);
        let entries = engine.dependency_index.lookup(&qualified);
        assert_eq!(
            entries.len(),
            1,
            "bare-path dep MUST canonicalize to qualified form at registration"
        );

        // Fire a write at the canonical path; recompute must run.
        let event = TreeChangeEvent {
            path: qualified.clone(),
            hash: lit_h,
            previous_hash: None,
            new_hash: Some(lit_h),
            change_type: entity_store::ChangeType::Modified,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx).unwrap();

        let result_path = format!("/{}/app/results/1", TEST_PID);
        assert!(
            li.get(&result_path).is_some(),
            "recompute MUST fire when a bare-path dep matches a write at its canonical form"
        );
    }

    #[test]
    fn test_convergence_check() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let identity_hash = Hash::compute("test", b"identity");

        // Store literal
        let lit = make_literal_int(42);
        let lit_h = cs.put(lit).unwrap();
        li.set(&format!("/{}/app/data/x", TEST_PID), lit_h);

        // Expression
        let lookup = make_tree_lookup("app/data/x");
        let lookup_h = cs.put(lookup.clone()).unwrap();
        li.set(&format!("/{}/app/expr/1", TEST_PID), lookup_h);

        // Subgraph
        let metadata = make_subgraph_metadata("app/expr/1", "app/results/1");
        let meta_h = cs.put(metadata).unwrap();
        li.set(&format!("/{}/system/compute/processes/test1", TEST_PID), meta_h);

        let engine = ComputeEngine::new(cs.clone(), li.clone(), TEST_PID.to_string(), identity_hash);
        engine.dependency_index.add(&format!("/{}/app/data/x", TEST_PID), DependencyEntry {
            expression_uri: "app/expr/1".into(),
            subgraph_path: "system/compute/processes/test1".into(),
        });

        let event = TreeChangeEvent {
            path: format!("/{}/app/data/x", TEST_PID),
            hash: lit_h,
            previous_hash: None,
            new_hash: Some(lit_h),
            change_type: entity_store::ChangeType::Modified,
            context: None,
        };

        // First evaluation — writes result
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx).unwrap();
        let result_hash_1 = li.get(&format!("/{}/app/results/1", TEST_PID));
        assert!(result_hash_1.is_some());

        // Second evaluation with same data — convergence check should prevent new write
        // (The hash should be the same)
        let mut ctx2 = ExecutionContext::default();
        engine.on_tree_change(&event, &mut ctx2).unwrap();
        let result_hash_2 = li.get(&format!("/{}/app/results/1", TEST_PID));
        assert_eq!(result_hash_1, result_hash_2);
    }

    #[test]
    fn test_rebuild_index() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let identity_hash = Hash::compute("test", b"identity");

        // Store a tree lookup expression
        let lookup = make_tree_lookup("app/data/x");
        let lookup_h = cs.put(lookup).unwrap();
        li.set(&format!("/{}/app/expr/1", TEST_PID), lookup_h);

        // Store subgraph metadata
        let metadata = make_subgraph_metadata("app/expr/1", "app/results/1");
        let meta_h = cs.put(metadata).unwrap();
        li.set(&format!("/{}/system/compute/processes/test1", TEST_PID), meta_h);

        let engine = ComputeEngine::new(cs.clone(), li.clone(), TEST_PID.to_string(), identity_hash);

        // Rebuild should find the subgraph and register its dependency
        engine.rebuild_index();

        let qualified = format!("/{}/app/data/x", TEST_PID);
        let entries = engine.dependency_index.lookup(&qualified);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].expression_uri, "app/expr/1");
    }
}
