use std::collections::{HashMap, HashSet};

use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::ContentStore;

use crate::eval::resolve_relative_path;
use crate::types::*;

// ---------------------------------------------------------------------------
// HandlerTarget — collected per compute/apply handler-mode call (§3.3, F3)
// ---------------------------------------------------------------------------

/// A handler dispatch target collected during install-time audit.
///
/// `resource` is `Some(rt)` when `compute/apply.resource` resolves to a static
/// `compute/literal` carrying a `system/protocol/resource-target` value (F3,
/// v3.10). Dynamic resources defer to runtime — `resource` is `None` and the
/// install-time check covers handler+operation only.
#[derive(Debug, Clone)]
pub struct HandlerTarget {
    pub path: String,
    pub operation: String,
    pub resource: Option<entity_capability::ResourceTarget>,
}

// ---------------------------------------------------------------------------
// Visitor trait — parameterized walker (§3.3, §7.1)
// ---------------------------------------------------------------------------

pub trait ExpressionVisitor {
    fn visit_tree_lookup(&mut self, path: &str);
    fn visit_handler_dispatch(
        &mut self,
        path: &str,
        operation: &str,
        resource: Option<entity_capability::ResourceTarget>,
    );
    fn visit_store_target(&mut self, path: &str);
    fn visit_hash_lookup(&mut self, _hash: &Hash, _path: Option<&str>) {}
    /// Static structural error encountered during walk (e.g., F5 — compute/apply
    /// with `capability` field but no `resource` field). Default impl ignores.
    fn visit_structural_error(&mut self, _message: &str) {}
    /// Static-literal `compute/apply.capability` reference: emitted once per
    /// `compute/apply` whose `capability` resolves to a `compute/literal` whose
    /// `value` is a hash bytes pointing at an actual capability entity. Used by
    /// the install audit to perform CP1 chain-root checks (see EXTENSION-COMPUTE
    /// §3.3, PROPOSAL-COHERENT-CAPABILITY-AUTHORITY CP1). Dynamic capability
    /// values (lookup-based) are NOT emitted — those are deferred to the runtime
    /// dual-check from PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING F2.
    fn visit_static_literal_capability(&mut self, _cap_hash: &Hash) {}
}

// ---------------------------------------------------------------------------
// Graph walker
// ---------------------------------------------------------------------------

pub fn walk_expression_graph(
    entity: &Entity,
    visitor: &mut dyn ExpressionVisitor,
    content_store: &dyn ContentStore,
    included: &HashMap<Hash, Entity>,
    root_path: Option<&str>,
) {
    let mut visited = HashSet::new();
    walk_recursive(entity, visitor, content_store, included, &mut visited, root_path);
}

fn walk_recursive(
    entity: &Entity,
    visitor: &mut dyn ExpressionVisitor,
    content_store: &dyn ContentStore,
    included: &HashMap<Hash, Entity>,
    visited: &mut HashSet<Hash>,
    root_path: Option<&str>,
) {
    if visited.contains(&entity.content_hash) {
        return;
    }
    visited.insert(entity.content_hash);

    let data = match decode_data(entity) {
        Some(d) => d,
        None => return,
    };

    match entity.entity_type.as_str() {
        TYPE_LOOKUP_TREE => {
            if let Some(path) = data_str(&data, "path") {
                let resolved = if data_bool(&data, "relative") == Some(true) {
                    resolve_relative_path(root_path, &path)
                } else {
                    path
                };
                visitor.visit_tree_lookup(&resolved);
            }
            return;
        }

        TYPE_LOOKUP_HASH => {
            if let Some(hash) = data_hash(&data, "hash") {
                let path = data_str(&data, "path").map(|p| {
                    if data_bool(&data, "relative") == Some(true) {
                        resolve_relative_path(root_path, &p)
                    } else {
                        p
                    }
                });
                visitor.visit_hash_lookup(&hash, path.as_deref());
            }
            return;
        }

        TYPE_APPLY => {
            if let Some(path) = data_str(&data, "path") {
                let operation = data_str(&data, "operation").unwrap_or_default();

                // F5 (v3.10): static structural check — capability without resource
                // is a category error. Detected at install so the failure surfaces
                // before the subgraph is committed.
                let capability_hash = data_hash(&data, "capability");
                let resource_hash = data_hash(&data, "resource");
                if capability_hash.is_some() && resource_hash.is_none() {
                    visitor.visit_structural_error(
                        "compute/apply with capability field MUST also have resource field",
                    );
                }

                // CP1 (PROPOSAL-COHERENT-CAPABILITY-AUTHORITY): when the
                // capability field resolves to a `compute/literal` whose value
                // is a hash, emit it for install-time R1 chain-root audit.
                // Dynamic values fall through and are checked at runtime.
                if let Some(cap_ref_hash) = &capability_hash {
                    if let Some(cap_lit) = resolve_static_literal_hash_value(
                        cap_ref_hash,
                        content_store,
                        included,
                    ) {
                        visitor.visit_static_literal_capability(&cap_lit);
                    }
                }

                // F3 (v3.10): collect the resource target when it resolves to a
                // static literal; dynamic resources resolve at runtime so the
                // handler-grant check at install covers handler+operation only.
                let static_resource = resource_hash
                    .as_ref()
                    .and_then(|h| resolve_static_resource_target(h, content_store, included));
                visitor.visit_handler_dispatch(&path, &operation, static_resource);

                if path == "system/compute/builtins/store"
                    || path.ends_with("/system/compute/builtins/store")
                {
                    if let Some(args) = data_hash_map(&data, "args") {
                        if let Some((_, path_hash)) = args.iter().find(|(k, _)| k == "path") {
                            if let Some(path_entity) = resolve_hash(path_hash, content_store, included) {
                                if path_entity.entity_type == TYPE_LITERAL {
                                    if let Some(lit_data) = decode_data(&path_entity) {
                                        if let Some(store_path) = data_str(&lit_data, "value") {
                                            visitor.visit_store_target(&store_path);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        TYPE_CLOSURE => {
            if let Some(env_hash) = data_hash(&data, "env") {
                if let Some(env) = resolve_hash(&env_hash, content_store, included) {
                    walk_recursive(&env, visitor, content_store, included, visited, root_path);
                }
            }
            if let Some(body_hash) = data_hash(&data, "body") {
                if let Some(body) = resolve_hash(&body_hash, content_store, included) {
                    walk_recursive(&body, visitor, content_store, included, visited, root_path);
                }
            }
            return;
        }

        _ => {}
    }

    walk_hash_fields(&data, visitor, content_store, included, visited, root_path);
}

fn walk_hash_fields(
    data: &Value,
    visitor: &mut dyn ExpressionVisitor,
    content_store: &dyn ContentStore,
    included: &HashMap<Hash, Entity>,
    visited: &mut HashSet<Hash>,
    root_path: Option<&str>,
) {
    match data {
        Value::Bytes(b) => {
            if let Ok(hash) = Hash::from_bytes(b) {
                if let Some(referenced) = resolve_hash(&hash, content_store, included) {
                    walk_recursive(&referenced, visitor, content_store, included, visited, root_path);
                }
            }
        }
        Value::Map(entries) => {
            for (_, v) in entries {
                walk_hash_fields(v, visitor, content_store, included, visited, root_path);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_hash_fields(item, visitor, content_store, included, visited, root_path);
            }
        }
        _ => {}
    }
}

fn resolve_hash(hash: &Hash, content_store: &dyn ContentStore, included: &HashMap<Hash, Entity>) -> Option<Entity> {
    if let Some(e) = included.get(hash) {
        return Some(e.clone());
    }
    content_store.get(hash)
}

/// Resolve a hash that may reference a `compute/literal` whose `value` is itself
/// a hash, returning that inner hash. Used by CP1 to extract the capability
/// hash from a static-literal `compute/apply.capability`. Returns `None` for
/// dynamic expressions (anything other than a literal-of-hash).
fn resolve_static_literal_hash_value(
    hash: &Hash,
    content_store: &dyn ContentStore,
    included: &HashMap<Hash, Entity>,
) -> Option<Hash> {
    let entity = resolve_hash(hash, content_store, included)?;
    if entity.entity_type != TYPE_LITERAL {
        return None;
    }
    let data = decode_data(&entity)?;
    let value = data.get("value")?;
    match value {
        Value::Bytes(b) => Hash::from_bytes(b).ok(),
        _ => None,
    }
}

/// Resolve a `compute/apply.resource` hash to a static `ResourceTarget` (F3).
///
/// Returns `Some` only when the referenced entity is a `compute/literal` whose
/// `value` field is a `system/protocol/resource-target`-shaped CBOR map
/// (`{targets: [...], exclude: [...]}`). Anything else — including dynamic
/// expressions that compute a resource at runtime — returns `None`, deferring
/// the resource check to runtime.
fn resolve_static_resource_target(
    hash: &Hash,
    content_store: &dyn ContentStore,
    included: &HashMap<Hash, Entity>,
) -> Option<entity_capability::ResourceTarget> {
    let entity = resolve_hash(hash, content_store, included)?;
    if entity.entity_type != TYPE_LITERAL {
        return None;
    }
    let data = decode_data(&entity)?;
    let value = data.get("value")?;
    decode_resource_target(value)
}

/// Decode a `system/protocol/resource-target` CBOR map (`{targets, exclude}`)
/// into a `ResourceTarget` struct. Returns `None` if the shape doesn't match.
pub(crate) fn decode_resource_target(v: &Value) -> Option<entity_capability::ResourceTarget> {
    let entries = match v {
        Value::Map(m) => m,
        _ => return None,
    };
    let mut targets = Vec::new();
    let mut exclude = Vec::new();
    for (k, val) in entries {
        let key = match k {
            Value::Text(s) => s.as_str(),
            _ => continue,
        };
        let arr = match val {
            Value::Array(a) => a,
            _ => continue,
        };
        let strings: Vec<String> = arr
            .iter()
            .filter_map(|x| match x {
                Value::Text(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        match key {
            "targets" => targets = strings,
            "exclude" => exclude = strings,
            _ => {}
        }
    }
    Some(entity_capability::ResourceTarget { targets, exclude })
}

// ---------------------------------------------------------------------------
// Concrete visitors
// ---------------------------------------------------------------------------

/// Collects tree lookup paths for dependency registration (§7.1).
#[derive(Default)]
pub struct DependencyCollector {
    pub paths: Vec<String>,
}

impl DependencyCollector {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExpressionVisitor for DependencyCollector {
    fn visit_tree_lookup(&mut self, path: &str) {
        self.paths.push(path.to_string());
    }
    fn visit_handler_dispatch(
        &mut self,
        _path: &str,
        _operation: &str,
        _resource: Option<entity_capability::ResourceTarget>,
    ) {}
    fn visit_store_target(&mut self, _path: &str) {}
}

/// Collects all impure operations for install-time audit (§3.3).
#[derive(Default)]
pub struct SubgraphAuditor {
    pub read_paths: Vec<String>,
    pub handler_targets: Vec<HandlerTarget>,
    pub write_paths: Vec<String>,
    pub data_hashes: Vec<(Hash, Option<String>)>,
    /// Static structural errors discovered during walk (F5 — capability without
    /// resource). Caller MUST reject the install when this is non-empty.
    pub structural_errors: Vec<String>,
    /// Static-literal `compute/apply.capability` hashes (CP1). Caller runs
    /// `identity_in_authority_chain` against the installer for each, before
    /// the resource-coverage check. Dynamic capability values are not collected
    /// here and are checked at runtime via the F2 dual-check.
    pub static_literal_capabilities: Vec<Hash>,
}

impl SubgraphAuditor {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExpressionVisitor for SubgraphAuditor {
    fn visit_tree_lookup(&mut self, path: &str) {
        self.read_paths.push(path.to_string());
    }
    fn visit_handler_dispatch(
        &mut self,
        path: &str,
        operation: &str,
        resource: Option<entity_capability::ResourceTarget>,
    ) {
        self.handler_targets.push(HandlerTarget {
            path: path.to_string(),
            operation: operation.to_string(),
            resource,
        });
    }
    fn visit_store_target(&mut self, path: &str) {
        self.write_paths.push(path.to_string());
    }
    fn visit_hash_lookup(&mut self, hash: &Hash, path: Option<&str>) {
        self.data_hashes.push((*hash, path.map(|s| s.to_string())));
    }
    fn visit_structural_error(&mut self, message: &str) {
        self.structural_errors.push(message.to_string());
    }
    fn visit_static_literal_capability(&mut self, cap_hash: &Hash) {
        self.static_literal_capabilities.push(*cap_hash);
    }
}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

pub fn walk_tree_lookups(
    entity: &Entity,
    content_store: &dyn ContentStore,
    included: &HashMap<Hash, Entity>,
    root_path: Option<&str>,
) -> Vec<String> {
    let mut collector = DependencyCollector::new();
    walk_expression_graph(entity, &mut collector, content_store, included, root_path);
    collector.paths
}

pub fn audit_subgraph(
    entity: &Entity,
    content_store: &dyn ContentStore,
    included: &HashMap<Hash, Entity>,
    root_path: Option<&str>,
) -> SubgraphAuditor {
    let mut auditor = SubgraphAuditor::new();
    walk_expression_graph(entity, &mut auditor, content_store, included, root_path);
    auditor
}

/// Deterministic subgraph ID: base32_lower_no_padding(sha256(utf8_bytes(root_path))) (§3.3).
pub fn deterministic_id(root_path: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(root_path.as_bytes());
    data_encoding::BASE32_NOPAD
        .encode(&digest)
        .to_lowercase()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{ContentStore, MemoryContentStore};

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

    fn make_arithmetic(op: &str, left: Hash, right: Hash) -> Entity {
        let data = entity_ecf::cbor_map! {
            "left" => Value::Bytes(left.to_bytes().to_vec()),
            "op" => entity_ecf::text(op),
            "right" => Value::Bytes(right.to_bytes().to_vec())
        };
        Entity::new(TYPE_ARITHMETIC, entity_ecf::to_ecf(&data)).unwrap()
    }

    #[test]
    fn test_walk_tree_lookups() {
        let cs = MemoryContentStore::new();
        let included = HashMap::new();

        let lookup_a = make_tree_lookup("app/data/a");
        let lookup_b = make_tree_lookup("app/data/b");
        let ah = cs.put(lookup_a).unwrap();
        let bh = cs.put(lookup_b).unwrap();

        let add = make_arithmetic("add", ah, bh);

        let paths = walk_tree_lookups(&add, &cs, &included, None);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"app/data/a".to_string()));
        assert!(paths.contains(&"app/data/b".to_string()));
    }

    #[test]
    fn test_audit_subgraph() {
        let cs = MemoryContentStore::new();
        let included = HashMap::new();

        let lookup = make_tree_lookup("app/cell/A1");
        let lh = cs.put(lookup).unwrap();

        let apply_data = entity_ecf::cbor_map! {
            "operation" => entity_ecf::text("eval"),
            "path" => entity_ecf::text("system/clock")
        };
        let apply = Entity::new(TYPE_APPLY, entity_ecf::to_ecf(&apply_data)).unwrap();
        let apply_h = cs.put(apply).unwrap();

        let root = make_arithmetic("add", lh, apply_h);

        let auditor = audit_subgraph(&root, &cs, &included, None);
        assert_eq!(auditor.read_paths, vec!["app/cell/A1"]);
        assert_eq!(auditor.handler_targets.len(), 1);
        assert_eq!(auditor.handler_targets[0].path, "system/clock");
        assert_eq!(auditor.handler_targets[0].operation, "eval");
        assert!(auditor.handler_targets[0].resource.is_none());
        assert!(auditor.structural_errors.is_empty());
    }

    #[test]
    fn test_audit_collects_static_literal_capability() {
        // CP1: a compute/apply with both `capability` and `resource` referencing
        // compute/literal entities that hold hashes — the walker should emit the
        // resolved capability hash via visit_static_literal_capability.
        let cs = MemoryContentStore::new();
        let included = HashMap::new();

        let target_cap_hash = Hash::compute("test", b"target-capability");

        // capability literal: { value: <target_cap_hash bytes> }
        let cap_lit_data = entity_ecf::cbor_map! {
            "value" => Value::Bytes(target_cap_hash.to_bytes().to_vec())
        };
        let cap_lit = Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&cap_lit_data)).unwrap();
        let cap_lit_h = cs.put(cap_lit).unwrap();

        // resource literal: a resource-target shaped value
        let res_lit_data = entity_ecf::cbor_map! {
            "value" => Value::Map(vec![
                (Value::Text("targets".into()),
                    Value::Array(vec![Value::Text("app/x".into())])),
                (Value::Text("exclude".into()), Value::Array(vec![])),
            ])
        };
        let res_lit = Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&res_lit_data)).unwrap();
        let res_lit_h = cs.put(res_lit).unwrap();

        // compute/apply { path, operation, capability: <cap_lit_h>, resource: <res_lit_h> }
        let apply_data = entity_ecf::cbor_map! {
            "operation" => entity_ecf::text("get"),
            "path" => entity_ecf::text("system/tree"),
            "capability" => Value::Bytes(cap_lit_h.to_bytes().to_vec()),
            "resource" => Value::Bytes(res_lit_h.to_bytes().to_vec())
        };
        let apply = Entity::new(TYPE_APPLY, entity_ecf::to_ecf(&apply_data)).unwrap();

        let auditor = audit_subgraph(&apply, &cs, &included, None);
        assert!(
            auditor.structural_errors.is_empty(),
            "no structural error expected"
        );
        assert_eq!(
            auditor.static_literal_capabilities,
            vec![target_cap_hash],
            "walker should collect the resolved capability hash for CP1"
        );
    }

    #[test]
    fn test_audit_dynamic_capability_not_collected() {
        // When `capability` references something other than compute/literal
        // (e.g., a tree lookup), the walker treats it as dynamic and does NOT
        // emit a static-literal capability — runtime check applies instead.
        let cs = MemoryContentStore::new();
        let included = HashMap::new();

        let dyn_cap = make_tree_lookup("app/dynamic-cap");
        let dyn_cap_h = cs.put(dyn_cap).unwrap();
        let res_lit_data = entity_ecf::cbor_map! {
            "value" => Value::Map(vec![
                (Value::Text("targets".into()),
                    Value::Array(vec![Value::Text("app/x".into())])),
                (Value::Text("exclude".into()), Value::Array(vec![])),
            ])
        };
        let res_lit = Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&res_lit_data)).unwrap();
        let res_lit_h = cs.put(res_lit).unwrap();

        let apply_data = entity_ecf::cbor_map! {
            "operation" => entity_ecf::text("get"),
            "path" => entity_ecf::text("system/tree"),
            "capability" => Value::Bytes(dyn_cap_h.to_bytes().to_vec()),
            "resource" => Value::Bytes(res_lit_h.to_bytes().to_vec())
        };
        let apply = Entity::new(TYPE_APPLY, entity_ecf::to_ecf(&apply_data)).unwrap();

        let auditor = audit_subgraph(&apply, &cs, &included, None);
        assert!(
            auditor.static_literal_capabilities.is_empty(),
            "dynamic capability must not be collected as static-literal"
        );
    }

    #[test]
    fn test_deterministic_id() {
        let id1 = deterministic_id("app/cell/A1");
        let id2 = deterministic_id("app/cell/A1");
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 52);
        assert!(id1.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));

        let id3 = deterministic_id("app/cell/B2");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_cycle_detection() {
        let cs = MemoryContentStore::new();
        let included = HashMap::new();

        // Self-referencing expression (would infinite loop without cycle detection)
        let placeholder = make_literal_int(0);
        let ph = cs.put(placeholder).unwrap();
        let arith = make_arithmetic("add", ph, ph);

        let paths = walk_tree_lookups(&arith, &cs, &included, None);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_walk_relative_tree_lookup() {
        let cs = MemoryContentStore::new();
        let included = HashMap::new();

        // Relative tree lookup: path="data/x", relative=true
        let data = entity_ecf::cbor_map! {
            "path" => entity_ecf::text("data/x"),
            "relative" => ciborium::Value::Bool(true)
        };
        let rel_lookup = Entity::new(TYPE_LOOKUP_TREE, entity_ecf::to_ecf(&data)).unwrap();
        let rlh = cs.put(rel_lookup).unwrap();

        // Absolute tree lookup: path="other/y"
        let abs_lookup = make_tree_lookup("other/y");
        let alh = cs.put(abs_lookup).unwrap();

        let root = make_arithmetic("add", rlh, alh);

        // Walk with root_path="app/job1"
        let paths = walk_tree_lookups(&root, &cs, &included, Some("app/job1"));
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"app/job1/data/x".to_string()));
        assert!(paths.contains(&"other/y".to_string()));
    }

    #[test]
    fn test_audit_relative_hash_lookup() {
        let cs = MemoryContentStore::new();
        let included = HashMap::new();

        let dummy_hash = Hash::compute("test", b"data");

        // Relative hash lookup: path="data/item", relative=true
        let data = entity_ecf::cbor_map! {
            "hash" => ciborium::Value::Bytes(dummy_hash.to_bytes().to_vec()),
            "path" => entity_ecf::text("data/item"),
            "relative" => ciborium::Value::Bool(true)
        };
        let lookup = Entity::new(TYPE_LOOKUP_HASH, entity_ecf::to_ecf(&data)).unwrap();

        let auditor = audit_subgraph(&lookup, &cs, &included, Some("app/root"));
        assert_eq!(auditor.data_hashes.len(), 1);
        assert_eq!(
            auditor.data_hashes[0].1.as_deref(),
            Some("app/root/data/item")
        );
    }
}
