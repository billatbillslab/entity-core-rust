//! Query extension — secondary indexes and find/count operations.
//!
//! Implements EXTENSION-QUERY.md Level 1:
//! - Type index, reverse hash index, path link index
//! - Query handler at `system/query` with `find` and `count` operations
//! - Capability-filtered results, cursor-based pagination

pub mod cursor;
pub mod index;
pub mod indexing;
#[cfg(feature = "sqlite")]
pub mod sqlite_index;
pub mod walker;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use entity_capability::{matches_scope, GrantEntry};
use entity_ecf::Value;
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_FORBIDDEN,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};


/// Default limit when not specified in expression (spec §8).
const DEFAULT_QUERY_LIMIT: u64 = 100;
/// Maximum limit value (spec §8).
const MAX_QUERY_LIMIT: u64 = 10_000;

// Re-exports
pub use index::{QueryIndexes, QueryIndexStore};
pub use indexing::IndexingLocationIndex;
#[cfg(feature = "sqlite")]
pub use sqlite_index::SqliteQueryIndexes;

// ---------------------------------------------------------------------------
// Query expression (parsed from params)
// ---------------------------------------------------------------------------

struct QueryExpression {
    type_filter: Option<String>,
    ref_filter: Option<Hash>,
    path_filter: Option<String>,
    path_prefix: Option<String>,
    limit: Option<u64>,
    cursor: Option<String>,
    include_entities: bool,
}

/// A single query match result.
#[derive(Debug, Clone)]
struct QueryMatch {
    path: String,
    hash: Hash,
    entity_type: String,
}

// ---------------------------------------------------------------------------
// Constraints decoded from matching grant
// ---------------------------------------------------------------------------

struct QueryConstraints {
    scope: String,           // "tree" or "content_store"
    max_results: Option<u64>,
    type_scope_include: Option<Vec<String>>,
    type_scope_exclude: Option<Vec<String>>,
}

impl Default for QueryConstraints {
    fn default() -> Self {
        Self {
            scope: "tree".to_string(),
            max_results: None,
            type_scope_include: None,
            type_scope_exclude: None,
        }
    }
}

fn parse_constraints(grant: &Option<GrantEntry>) -> QueryConstraints {
    let grant = match grant {
        Some(g) => g,
        None => return QueryConstraints::default(),
    };

    let mut result = QueryConstraints::default();

    // Read scope from allowances (expanding field — absent = tree-only)
    if let Some(ref allowances) = grant.allowances {
        if let Some(scope_val) = allowances.get("scope") {
            if let Some(s) = scope_val.as_text() {
                result.scope = s.to_string();
            }
        }
    }

    // Read max_results and type_scope from constraints (narrowing fields)
    if let Some(ref constraints) = grant.constraints {
        if let Some(max_val) = constraints.get("max_results") {
            if let Some(ciborium::Value::Integer(i)) = Some(max_val) {
                let n: i128 = (*i).into();
                if n > 0 {
                    result.max_results = Some(n as u64);
                }
            }
        }
        if let Some(type_scope_val) = constraints.get("type_scope") {
            if let Some(scope_map) = type_scope_val.as_map() {
                for (sk, sv) in scope_map {
                    match sk.as_text() {
                        Some("include") => {
                            if let Some(arr) = sv.as_array() {
                                result.type_scope_include = Some(
                                    arr.iter()
                                        .filter_map(|v| v.as_text().map(String::from))
                                        .collect(),
                                );
                            }
                        }
                        Some("exclude") => {
                            if let Some(arr) = sv.as_array() {
                                result.type_scope_exclude = Some(
                                    arr.iter()
                                        .filter_map(|v| v.as_text().map(String::from))
                                        .collect(),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// QueryHandler
// ---------------------------------------------------------------------------

pub struct QueryHandler {
    indexes: Arc<dyn QueryIndexStore>,
    content_store: Arc<dyn ContentStore>,
    #[allow(dead_code)]
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
}

impl QueryHandler {
    pub fn new(
        indexes: Arc<dyn QueryIndexStore>,
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/query", local_peer_id);
        Self {
            indexes,
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
        }
    }

    fn handle_find(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let expr = parse_expression(&ctx.params)?;
        let constraints = parse_constraints(&ctx.matching_grant);

        // Validate content_store scope requires type_scope (spec §5.5.2)
        if constraints.scope == "content_store" && constraints.type_scope_include.is_none() {
            return Ok(HandlerResult::error(
                STATUS_FORBIDDEN,
                make_error_entity("content_store_requires_type_scope",
                    "content_store scope requires type_scope on grant constraints"),
            ));
        }

        // Validate type_filter against type_scope (spec §5.1 step 3)
        if let (Some(ref type_filter), Some(ref type_scope)) =
            (&expr.type_filter, &constraints.type_scope_include)
        {
            let exclude = constraints.type_scope_exclude.as_deref().unwrap_or(&[]);
            if !matches_scope(type_filter, type_scope, exclude, &self.local_peer_id) {
                return Ok(HandlerResult::error(
                    STATUS_FORBIDDEN,
                    make_error_entity("type_not_authorized", "type_filter not in type_scope"),
                ));
            }
        }

        // Validate: empty query → 400
        if expr.type_filter.is_none()
            && expr.ref_filter.is_none()
            && expr.path_filter.is_none()
            && expr.path_prefix.is_none()
        {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                make_error_entity("empty_query", "at least one filter is required"),
            ));
        }

        // Execute index lookups and intersect
        let candidates = self.execute_query(&expr);

        // Capability filter
        let filtered = self.filter_by_capability(candidates, &constraints, ctx);

        // Sort by path ascending
        let mut sorted = filtered;
        sorted.sort_by(|a, b| a.path.cmp(&b.path));

        // Effective limit
        let effective_limit = std::cmp::min(
            expr.limit.unwrap_or(DEFAULT_QUERY_LIMIT),
            constraints.max_results.unwrap_or(MAX_QUERY_LIMIT),
        );

        // Pagination
        let total = sorted.len() as u64;
        let start = if let Some(ref cursor_str) = expr.cursor {
            let last_path = cursor::decode_cursor(cursor_str)?;
            sorted
                .iter()
                .position(|m| m.path > last_path)
                .unwrap_or(sorted.len())
        } else {
            0
        };

        let page: Vec<&QueryMatch> = sorted
            .iter()
            .skip(start)
            .take(effective_limit as usize)
            .collect();

        let has_more = start + page.len() < sorted.len();
        let next_cursor = if has_more {
            page.last().map(|m| cursor::encode_cursor(&m.path))
        } else {
            None
        };

        // Build result entity
        let matches: Vec<Value> = page
            .iter()
            .map(|m| {
                Value::Map(vec![
                    (entity_ecf::text("hash"), Value::Bytes(m.hash.to_bytes().to_vec())),
                    (entity_ecf::text("path"), entity_ecf::text(&m.path)),
                    (entity_ecf::text("type"), entity_ecf::text(&m.entity_type)),
                ])
            })
            .collect();

        let mut result_entries = vec![
            (
                entity_ecf::text("has_more"),
                entity_ecf::bool_val(has_more),
            ),
            (
                entity_ecf::text("matches"),
                Value::Array(matches),
            ),
            (
                entity_ecf::text("total"),
                entity_ecf::integer(total as i64),
            ),
        ];
        if let Some(ref cursor_val) = next_cursor {
            result_entries.push((entity_ecf::text("cursor"), entity_ecf::text(cursor_val)));
        }

        let result_data = entity_ecf::to_ecf(&Value::Map(result_entries));
        let result_entity = Entity::new("system/query/result", result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        if expr.include_entities {
            let mut included = HashMap::new();
            for m in &page {
                if let Some(entity) = self.content_store.get(&m.hash) {
                    included.insert(m.hash, entity);
                }
            }
            Ok(HandlerResult::ok(build_envelope_result(result_entity, included)))
        } else {
            Ok(HandlerResult::ok(result_entity))
        }
    }

    fn handle_count(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let expr = parse_expression(&ctx.params)?;
        let constraints = parse_constraints(&ctx.matching_grant);

        if constraints.scope == "content_store" && constraints.type_scope_include.is_none() {
            return Ok(HandlerResult::error(
                STATUS_FORBIDDEN,
                make_error_entity("content_store_requires_type_scope",
                    "content_store scope requires type_scope on grant constraints"),
            ));
        }

        if expr.type_filter.is_none()
            && expr.ref_filter.is_none()
            && expr.path_filter.is_none()
            && expr.path_prefix.is_none()
        {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                make_error_entity("empty_query", "at least one filter is required"),
            ));
        }

        let candidates = self.execute_query(&expr);
        let filtered = self.filter_by_capability(candidates, &constraints, ctx);
        let count = filtered.len() as i64;

        let result_data = entity_ecf::to_ecf(&entity_ecf::integer(count));
        let result_entity = Entity::new("primitive/uint", result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        Ok(HandlerResult::ok(result_entity))
    }

    fn execute_query(&self, expr: &QueryExpression) -> Vec<QueryMatch> {
        let mut result_sets: Vec<Vec<QueryMatch>> = Vec::new();

        // Type index lookup
        if let Some(ref type_filter) = expr.type_filter {
            let type_entries = self.indexes.query_type_index(type_filter);
            result_sets.push(
                type_entries
                    .into_iter()
                    .map(|e| {
                        // Get entity type from the cache via content store lookup
                        let entity_type = self
                            .content_store
                            .get(&e.hash)
                            .map(|ent| ent.entity_type)
                            .unwrap_or_default();
                        QueryMatch {
                            path: e.path,
                            hash: e.hash,
                            entity_type,
                        }
                    })
                    .collect(),
            );
        }

        // Reverse hash index lookup
        if let Some(ref ref_hash) = expr.ref_filter {
            let ref_entries = self.indexes.query_reverse_index(ref_hash);
            result_sets.push(
                ref_entries
                    .into_iter()
                    .map(|e| {
                        let hash = self
                            .indexes
                            .query_type_index(&e.source_type)
                            .into_iter()
                            .find(|t| t.path == e.source_path)
                            .map(|t| t.hash)
                            .unwrap_or(Hash::zero());
                        QueryMatch {
                            path: e.source_path,
                            hash,
                            entity_type: e.source_type,
                        }
                    })
                    .collect(),
            );
        }

        // Path link index lookup
        if let Some(ref path_filter) = expr.path_filter {
            let link_entries = self.indexes.query_path_link_index(path_filter);
            result_sets.push(
                link_entries
                    .into_iter()
                    .map(|e| {
                        let hash = self
                            .indexes
                            .query_type_index(&e.source_type)
                            .into_iter()
                            .find(|t| t.path == e.source_path)
                            .map(|t| t.hash)
                            .unwrap_or(Hash::zero());
                        QueryMatch {
                            path: e.source_path,
                            hash,
                            entity_type: e.source_type,
                        }
                    })
                    .collect(),
            );
        }

        // If no index was queried but path_prefix is present, scan type index
        if result_sets.is_empty() {
            if let Some(ref _prefix) = expr.path_prefix {
                let all = self.indexes.query_type_index("*");
                result_sets.push(
                    all.into_iter()
                        .map(|e| {
                            let entity_type = self
                                .content_store
                                .get(&e.hash)
                                .map(|ent| ent.entity_type)
                                .unwrap_or_default();
                            QueryMatch {
                                path: e.path,
                                hash: e.hash,
                                entity_type,
                            }
                        })
                        .collect(),
                );
            }
        }

        // Intersect result sets
        let mut candidates = match result_sets.len() {
            0 => return Vec::new(),
            1 => result_sets.into_iter().next().unwrap(),
            _ => {
                let mut iter = result_sets.into_iter();
                let first = iter.next().unwrap();
                let first_paths: std::collections::HashSet<String> =
                    first.iter().map(|m| m.path.clone()).collect();
                let mut intersection = first;

                for set in iter {
                    let paths: std::collections::HashSet<String> =
                        set.iter().map(|m| m.path.clone()).collect();
                    let common: std::collections::HashSet<&String> =
                        first_paths.intersection(&paths).collect();
                    intersection.retain(|m| common.contains(&m.path));
                }
                intersection
            }
        };

        // Apply path_prefix filter.
        // Paths in the index are peer-qualified ({peer_id}/path). The expression's
        // path_prefix is a bare path. We qualify it so it matches indexed paths.
        if let Some(ref prefix) = expr.path_prefix {
            let qualified_prefix = entity_entity::EntityUri::qualify_path(prefix, &self.local_peer_id);
            candidates.retain(|m| m.path.starts_with(&qualified_prefix));
        }

        candidates
    }

    fn filter_by_capability(
        &self,
        candidates: Vec<QueryMatch>,
        constraints: &QueryConstraints,
        ctx: &HandlerContext,
    ) -> Vec<QueryMatch> {
        // For internal dispatch (no capability), return all
        if ctx.caller_capability.is_none() {
            return candidates;
        }

        let cap = ctx.caller_capability.as_ref().unwrap();

        candidates
            .into_iter()
            .filter(|candidate| {
                // Type check
                if let Some(ref type_include) = constraints.type_scope_include {
                    let type_exclude = constraints.type_scope_exclude.as_deref().unwrap_or(&[]);
                    if !matches_scope(
                        &candidate.entity_type,
                        type_include,
                        type_exclude,
                        &self.local_peer_id,
                    ) {
                        return false;
                    }
                }

                // Path check — tree scope requires path permission
                if constraints.scope == "tree" {
                    // Check resource scope against caller's capability
                    for grant in &cap.grants {
                        if matches_scope(
                            &candidate.path,
                            &grant.resources.include,
                            &grant.resources.exclude,
                            &self.local_peer_id,
                        ) {
                            return true;
                        }
                    }
                    return false;
                }

                true
            })
            .collect()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for QueryHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "find" => self.handle_find(ctx),
            "count" => self.handle_count(ctx),
            _ => Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                make_error_entity(
                    "unknown_operation",
                    &format!("unknown operation: {}", ctx.operation),
                ),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "query"
    }

    fn operations(&self) -> &[&str] {
        &["find", "count"]
    }
}

// ---------------------------------------------------------------------------
// Expression parsing
// ---------------------------------------------------------------------------

fn parse_expression(params: &Entity) -> Result<QueryExpression, HandlerError> {
    let value: ciborium::Value = ciborium::from_reader(params.data.as_slice())
        .map_err(|e| HandlerError::InvalidParams(format!("invalid expression: {e}")))?;

    let map = value
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("expression must be a map".into()))?;

    let mut expr = QueryExpression {
        type_filter: None,
        ref_filter: None,
        path_filter: None,
        path_prefix: None,
        limit: None,
        cursor: None,
        include_entities: false,
    };

    for (k, v) in map {
        match k.as_text() {
            Some("type_filter") => {
                expr.type_filter = v.as_text().map(String::from);
            }
            Some("ref_filter") => {
                if let Some(bytes) = v.as_bytes() {
                    expr.ref_filter = Hash::from_bytes(bytes).ok();
                }
            }
            Some("path_filter") => {
                expr.path_filter = v.as_text().map(String::from);
            }
            Some("path_prefix") => {
                expr.path_prefix = v.as_text().map(String::from);
            }
            Some("limit") => {
                if let Some(ciborium::Value::Integer(i)) = Some(v) {
                    let n: i128 = (*i).into();
                    if n > 0 {
                        expr.limit = Some(n as u64);
                    }
                }
            }
            Some("cursor") => {
                expr.cursor = v.as_text().map(String::from);
            }
            Some("include_entities") => {
                expr.include_entities = v.as_bool().unwrap_or(false);
            }
            // Silently ignore Level 2 fields (field_filters, order_by, descending)
            _ => {}
        }
    }

    // Validate: field_filters requires type_filter (Level 2, but validate anyway)
    // (silently ignored at Level 1 per spec §5.2)

    Ok(expr)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_error_entity(code: &str, message: &str) -> Entity {
    let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
        "code" => entity_ecf::text(code),
        "message" => entity_ecf::text(message)
    });
    Entity::new(entity_types::TYPE_ERROR, data).unwrap()
}

fn entity_to_inline(entity: &Entity) -> Value {
    let data_value: Value = ciborium::from_reader(entity.data.as_slice())
        .unwrap_or(Value::Null);
    Value::Map(vec![
        (entity_ecf::text("content_hash"), Value::Bytes(entity.content_hash.to_bytes().to_vec())),
        (entity_ecf::text("data"), data_value),
        (entity_ecf::text("type"), entity_ecf::text(&entity.entity_type)),
    ])
}

fn build_envelope_result(root: Entity, included: HashMap<Hash, Entity>) -> Entity {
    let included_entries: Vec<_> = included
        .iter()
        .map(|(hash, entity)| {
            (Value::Bytes(hash.to_bytes().to_vec()), entity_to_inline(entity))
        })
        .collect();

    let mut envelope_fields = vec![(entity_ecf::text("root"), entity_to_inline(&root))];
    if !included_entries.is_empty() {
        envelope_fields.push((
            entity_ecf::text("included"),
            Value::Map(included_entries),
        ));
    }

    let data = entity_ecf::to_ecf(&Value::Map(envelope_fields));
    Entity::new(entity_types::TYPE_ENVELOPE, data)
        .expect("envelope entity creation should not fail")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_handler::STATUS_OK;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn setup() -> (Arc<QueryIndexes>, Arc<MemoryContentStore>, Arc<MemoryLocationIndex>, QueryHandler) {
        let content_store = Arc::new(MemoryContentStore::new());
        let location_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing = Arc::new(indexing::IndexingLocationIndex::new(
            location_index.clone() as Arc<dyn LocationIndex>,
            content_store.clone() as Arc<dyn ContentStore>,
            indexes.clone(),
        ));
        let handler = QueryHandler::new(
            indexes.clone(),
            content_store.clone() as Arc<dyn ContentStore>,
            indexing as Arc<dyn LocationIndex>,
            "test_peer".to_string(),
        );
        (indexes, content_store, location_index, handler)
    }

    fn put_entity(
        cs: &Arc<MemoryContentStore>,
        li: &Arc<MemoryLocationIndex>,
        indexes: &Arc<QueryIndexes>,
        path: &str,
        entity_type: &str,
        data_val: &str,
    ) -> Hash {
        let entity = Entity::new(
            entity_type,
            entity_ecf::to_ecf(&entity_ecf::text(data_val)),
        ).unwrap();
        let hash = cs.put(entity.clone()).unwrap();
        li.set(path, hash);
        indexes.add_entries_for_entity(path, &entity);
        hash
    }

    fn make_find_ctx(expr_data: Value) -> HandlerContext {
        let params = Entity::new(
            "system/query/expression",
            entity_ecf::to_ecf(&expr_data),
        ).unwrap();
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: params.clone(),
            params,
            pattern: "test_peer/system/query".to_string(),
            suffix: String::new(),
            resource_target: None,
            author: None,
            request_id: "test".to_string(),
            operation: "find".to_string(),
            execute_fn: None,
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
            session_peer_id: None,
        }
    }

    #[tokio::test]
    async fn test_find_by_type() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "users/bob", "app/user", "bob");
        put_entity(&cs, &li, &indexes, "orders/o1", "app/order", "order1");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let result_val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = result_val.as_map().unwrap();
        let total = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap();
        let total_val: i128 = total.into();
        assert_eq!(total_val, 2);
    }

    #[tokio::test]
    async fn test_find_with_path_prefix() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "/test_peer/app/users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "/test_peer/app/users/bob", "app/user", "bob");
        put_entity(&cs, &li, &indexes, "/test_peer/other/users/carol", "app/user", "carol");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "path_prefix" => entity_ecf::text("app/users/")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let result_val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = result_val.as_map().unwrap();
        let total: i128 = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into();
        assert_eq!(total, 2);
    }

    #[tokio::test]
    async fn test_find_by_ref() {
        let (indexes, cs, li, handler) = setup();
        let target = Hash::compute("target", b"target_data");
        let ref_entity = Entity::new(
            "app/reference",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "target" => Value::Bytes(target.to_bytes().to_vec())
            }),
        ).unwrap();
        let ref_hash = cs.put(ref_entity.clone()).unwrap();
        li.set("refs/r1", ref_hash);
        indexes.add_entries_for_entity("refs/r1", &ref_entity);

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "ref_filter" => Value::Bytes(target.to_bytes().to_vec())
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let result_val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = result_val.as_map().unwrap();
        let total: i128 = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("total"))
            .unwrap()
            .1
            .as_integer()
            .unwrap()
            .into();
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn test_count() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "users/bob", "app/user", "bob");

        let params = Entity::new(
            "system/query/expression",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "type_filter" => entity_ecf::text("app/user")
            }),
        ).unwrap();
        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.operation = "count".to_string();
        ctx.params = params;
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let count: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let n: i128 = count.as_integer().unwrap().into();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn test_empty_query_rejected() {
        let (_indexes, _cs, _li, handler) = setup();
        let ctx = make_find_ctx(entity_ecf::cbor_map! {});
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_pagination() {
        let (indexes, cs, li, handler) = setup();
        for i in 0..5 {
            put_entity(
                &cs, &li, &indexes,
                &format!("users/user_{:02}", i),
                "app/user",
                &format!("user_{}", i),
            );
        }

        // Page 1: limit 2
        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "limit" => entity_ecf::integer(2)
        });
        let result = handler.handle(&ctx).await.unwrap();
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let has_more = map.iter().find(|(k, _)| k.as_text() == Some("has_more")).unwrap().1.as_bool().unwrap();
        assert!(has_more);
        let cursor_val = map.iter().find(|(k, _)| k.as_text() == Some("cursor")).unwrap().1.as_text().unwrap();
        let matches = map.iter().find(|(k, _)| k.as_text() == Some("matches")).unwrap().1.as_array().unwrap();
        assert_eq!(matches.len(), 2);

        // Page 2: use cursor
        let ctx2 = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "limit" => entity_ecf::integer(2),
            "cursor" => entity_ecf::text(cursor_val)
        });
        let result2 = handler.handle(&ctx2).await.unwrap();
        let val2: ciborium::Value = ciborium::from_reader(result2.result.data.as_slice()).unwrap();
        let map2 = val2.as_map().unwrap();
        let matches2 = map2.iter().find(|(k, _)| k.as_text() == Some("matches")).unwrap().1.as_array().unwrap();
        assert_eq!(matches2.len(), 2);
        let has_more2 = map2.iter().find(|(k, _)| k.as_text() == Some("has_more")).unwrap().1.as_bool().unwrap();
        assert!(has_more2);

        // Page 3: last page
        let cursor_val2 = map2.iter().find(|(k, _)| k.as_text() == Some("cursor")).unwrap().1.as_text().unwrap();
        let ctx3 = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "limit" => entity_ecf::integer(2),
            "cursor" => entity_ecf::text(cursor_val2)
        });
        let result3 = handler.handle(&ctx3).await.unwrap();
        let val3: ciborium::Value = ciborium::from_reader(result3.result.data.as_slice()).unwrap();
        let map3 = val3.as_map().unwrap();
        let matches3 = map3.iter().find(|(k, _)| k.as_text() == Some("matches")).unwrap().1.as_array().unwrap();
        assert_eq!(matches3.len(), 1);
        let has_more3 = map3.iter().find(|(k, _)| k.as_text() == Some("has_more")).unwrap().1.as_bool().unwrap();
        assert!(!has_more3);
    }

    #[tokio::test]
    async fn test_include_entities() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "include_entities" => entity_ecf::bool_val(true)
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_ENVELOPE);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let has_included = map.iter().any(|(k, _)| k.as_text() == Some("included"));
        assert!(has_included, "envelope should contain included entities");
    }

    #[tokio::test]
    async fn test_glob_type_filter() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "orders/o1", "app/order", "order1");
        put_entity(&cs, &li, &indexes, "system/cfg", "system/config", "cfg");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/*")
        });
        let result = handler.handle(&ctx).await.unwrap();
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map.iter().find(|(k, _)| k.as_text() == Some("total")).unwrap().1.as_integer().unwrap().into();
        assert_eq!(total, 2);
    }

    // --- Capability constraint tests ---

    #[tokio::test]
    async fn test_query_type_scope_filtering() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "orders/o1", "app/order", "order1");

        // Grant with type_scope only allowing "app/user"
        let grant = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["*".into()]),
            resources: entity_capability::PathScope::new(vec!["*".into()]),
            operations: entity_capability::IdScope::new(vec!["*".into()]),
            peers: None,
            constraints: Some(std::collections::BTreeMap::from([
                ("type_scope".to_string(), ciborium::Value::Map(vec![
                    (ciborium::Value::Text("include".into()),
                     ciborium::Value::Array(vec![ciborium::Value::Text("app/user".into())])),
                ])),
            ])),
            allowances: None,
        };
        let cap = entity_capability::CapabilityToken {
            grants: vec![grant.clone()],
            granter: entity_capability::Granter::Single(entity_hash::Hash::zero()),
            grantee: entity_hash::Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };

        // Query for exact type "app/user" — allowed by type_scope
        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.matching_grant = Some(grant.clone());
        ctx.caller_capability = Some(cap.clone());

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map.iter().find(|(k, _)| k.as_text() == Some("total")).unwrap().1.as_integer().unwrap().into();
        assert_eq!(total, 1); // only alice (app/user)

        // Query for "app/order" — blocked by type_scope (not in include list)
        let mut ctx2 = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/order")
        });
        ctx2.matching_grant = Some(grant.clone());
        ctx2.caller_capability = Some(cap.clone());
        let result2 = handler.handle(&ctx2).await.unwrap();
        assert_eq!(result2.status, STATUS_FORBIDDEN);

        // Query with glob "app/*" — rejected because glob is wider than type_scope
        let mut ctx3 = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/*")
        });
        ctx3.matching_grant = Some(grant);
        ctx3.caller_capability = Some(cap);
        let result3 = handler.handle(&ctx3).await.unwrap();
        assert_eq!(result3.status, STATUS_FORBIDDEN);
    }

    #[tokio::test]
    async fn test_query_max_results_constraint() {
        let (indexes, cs, li, handler) = setup();
        for i in 0..10 {
            put_entity(&cs, &li, &indexes, &format!("users/u{:02}", i), "app/user", &format!("user{}", i));
        }

        // Grant with max_results: 3
        let grant = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["*".into()]),
            resources: entity_capability::PathScope::new(vec!["*".into()]),
            operations: entity_capability::IdScope::new(vec!["*".into()]),
            peers: None,
            constraints: Some(std::collections::BTreeMap::from([
                ("max_results".to_string(), ciborium::Value::Integer(3.into())),
            ])),
            allowances: None,
        };

        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.matching_grant = Some(grant);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let matches = map.iter().find(|(k, _)| k.as_text() == Some("matches")).unwrap().1.as_array().unwrap();
        assert_eq!(matches.len(), 3); // limited by max_results
        let has_more = map.iter().find(|(k, _)| k.as_text() == Some("has_more")).unwrap().1.as_bool().unwrap();
        assert!(has_more);
    }

    #[tokio::test]
    async fn test_query_content_store_scope_requires_type_scope() {
        let (_indexes, _cs, _li, handler) = setup();

        // Grant with content_store scope (allowance) but no type_scope → should be 403
        let grant = entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["*".into()]),
            resources: entity_capability::PathScope::new(vec!["*".into()]),
            operations: entity_capability::IdScope::new(vec!["*".into()]),
            peers: None,
            constraints: None,
            allowances: Some(std::collections::BTreeMap::from([
                ("scope".to_string(), ciborium::Value::Text("content_store".into())),
            ])),
        };

        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.matching_grant = Some(grant);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_FORBIDDEN);
    }

    // --- Multi-filter intersection tests ---

    #[tokio::test]
    async fn test_find_type_and_ref_intersection() {
        let (indexes, cs, li, handler) = setup();
        let target = entity_hash::Hash::compute("target", b"target_data");

        // Entity A: app/user, references target
        let e_a = Entity::new("app/user", entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "name" => entity_ecf::text("alice"),
            "ref" => Value::Bytes(target.to_bytes().to_vec())
        })).unwrap();
        let h_a = cs.put(e_a.clone()).unwrap();
        li.set("users/alice", h_a);
        indexes.add_entries_for_entity("users/alice", &e_a);

        // Entity B: app/order, also references target
        let e_b = Entity::new("app/order", entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "id" => entity_ecf::text("o1"),
            "user_ref" => Value::Bytes(target.to_bytes().to_vec())
        })).unwrap();
        let h_b = cs.put(e_b.clone()).unwrap();
        li.set("orders/o1", h_b);
        indexes.add_entries_for_entity("orders/o1", &e_b);

        // Query: type=app/user AND ref_filter=target → should only return alice
        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "ref_filter" => Value::Bytes(target.to_bytes().to_vec())
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map.iter().find(|(k, _)| k.as_text() == Some("total")).unwrap().1.as_integer().unwrap().into();
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn test_find_type_and_path_prefix_intersection() {
        let (indexes, cs, li, handler) = setup();
        put_entity(&cs, &li, &indexes, "/test_peer/team/eng/alice", "app/user", "alice");
        put_entity(&cs, &li, &indexes, "/test_peer/team/sales/bob", "app/user", "bob");
        put_entity(&cs, &li, &indexes, "/test_peer/team/eng/carol", "app/user", "carol");

        // Query: type=app/user AND path_prefix=team/eng/
        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "path_prefix" => entity_ecf::text("team/eng/")
        });
        let result = handler.handle(&ctx).await.unwrap();
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map.iter().find(|(k, _)| k.as_text() == Some("total")).unwrap().1.as_integer().unwrap().into();
        assert_eq!(total, 2); // alice and carol, not bob
    }

    // --- Edge cases ---

    #[tokio::test]
    async fn test_find_no_results() {
        let (_indexes, _cs, _li, handler) = setup();
        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/nonexistent")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let total: i128 = map.iter().find(|(k, _)| k.as_text() == Some("total")).unwrap().1.as_integer().unwrap().into();
        assert_eq!(total, 0);
        let has_more = map.iter().find(|(k, _)| k.as_text() == Some("has_more")).unwrap().1.as_bool().unwrap();
        assert!(!has_more);
    }

    #[tokio::test]
    async fn test_unknown_operation() {
        let (_indexes, _cs, _li, handler) = setup();
        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.operation = "delete_all".to_string();
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }
}

// ---------------------------------------------------------------------------
// SQLite backend handler tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "sqlite")]
mod sqlite_handler_tests {
    use super::*;
    use entity_handler::STATUS_OK;
    use entity_store::sqlite::SqliteStore;

    fn setup_sqlite() -> (Arc<dyn QueryIndexStore>, Arc<dyn ContentStore>, Arc<dyn LocationIndex>, QueryHandler) {
        let store = SqliteStore::open_in_memory().unwrap();
        let content_store: Arc<dyn ContentStore> = Arc::new(store.content_store());
        let location_index: Arc<dyn LocationIndex> = Arc::new(store.location_index());
        let indexes: Arc<dyn QueryIndexStore> = Arc::new(
            crate::sqlite_index::SqliteQueryIndexes::new(store.connection()).unwrap()
        );
        let indexing: Arc<dyn LocationIndex> = Arc::new(indexing::IndexingLocationIndex::new(
            location_index.clone(),
            content_store.clone(),
            indexes.clone(),
        ));
        let handler = QueryHandler::new(
            indexes.clone(),
            content_store.clone(),
            indexing,
            "test_peer".to_string(),
        );
        (indexes, content_store, location_index, handler)
    }

    fn put_entity_sqlite(
        cs: &Arc<dyn ContentStore>,
        li: &Arc<dyn LocationIndex>,
        indexes: &Arc<dyn QueryIndexStore>,
        path: &str,
        entity_type: &str,
        data_val: &str,
    ) {
        let entity = Entity::new(
            entity_type,
            entity_ecf::to_ecf(&entity_ecf::text(data_val)),
        ).unwrap();
        let hash = cs.put(entity.clone()).unwrap();
        li.set(path, hash);
        indexes.add_entries_for_entity(path, &entity);
    }

    fn make_find_ctx(expr_data: Value) -> HandlerContext {
        let params = Entity::new(
            "system/query/expression",
            entity_ecf::to_ecf(&expr_data),
        ).unwrap();
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: params.clone(),
            params,
            pattern: "test_peer/system/query".to_string(),
            suffix: String::new(),
            resource_target: None,
            author: None,
            request_id: "test".to_string(),
            operation: "find".to_string(),
            execute_fn: None,
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
            session_peer_id: None,
        }
    }

    fn extract_total(result: &HandlerResult) -> i128 {
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        map.iter().find(|(k, _)| k.as_text() == Some("total")).unwrap().1.as_integer().unwrap().into()
    }

    #[tokio::test]
    async fn test_sqlite_find_by_type() {
        let (indexes, cs, li, handler) = setup_sqlite();
        put_entity_sqlite(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity_sqlite(&cs, &li, &indexes, "users/bob", "app/user", "bob");
        put_entity_sqlite(&cs, &li, &indexes, "orders/o1", "app/order", "order1");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(extract_total(&result), 2);
    }

    #[tokio::test]
    async fn test_sqlite_find_glob() {
        let (indexes, cs, li, handler) = setup_sqlite();
        put_entity_sqlite(&cs, &li, &indexes, "users/alice", "app/user", "alice");
        put_entity_sqlite(&cs, &li, &indexes, "orders/o1", "app/order", "order1");
        put_entity_sqlite(&cs, &li, &indexes, "cfg/x", "system/config", "x");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/*")
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(extract_total(&result), 2);
    }

    #[tokio::test]
    async fn test_sqlite_count() {
        let (indexes, cs, li, handler) = setup_sqlite();
        put_entity_sqlite(&cs, &li, &indexes, "users/a", "app/user", "a");
        put_entity_sqlite(&cs, &li, &indexes, "users/b", "app/user", "b");
        put_entity_sqlite(&cs, &li, &indexes, "users/c", "app/user", "c");

        let mut ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user")
        });
        ctx.operation = "count".to_string();
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let count: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let n: i128 = count.as_integer().unwrap().into();
        assert_eq!(n, 3);
    }

    #[tokio::test]
    async fn test_sqlite_pagination() {
        let (indexes, cs, li, handler) = setup_sqlite();
        for i in 0..5 {
            put_entity_sqlite(&cs, &li, &indexes, &format!("u/u{:02}", i), "app/user", &format!("u{}", i));
        }

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "limit" => entity_ecf::integer(2)
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let matches = map.iter().find(|(k, _)| k.as_text() == Some("matches")).unwrap().1.as_array().unwrap();
        assert_eq!(matches.len(), 2);
        let has_more = map.iter().find(|(k, _)| k.as_text() == Some("has_more")).unwrap().1.as_bool().unwrap();
        assert!(has_more);
        assert_eq!(extract_total(&result), 5);
    }

    #[tokio::test]
    async fn test_sqlite_find_by_ref() {
        let (indexes, cs, li, handler) = setup_sqlite();
        let target = entity_hash::Hash::compute("target", b"target_data");
        let entity = Entity::new(
            "app/reference",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "target" => Value::Bytes(target.to_bytes().to_vec())
            }),
        ).unwrap();
        let hash = cs.put(entity.clone()).unwrap();
        li.set("refs/r1", hash);
        indexes.add_entries_for_entity("refs/r1", &entity);

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "ref_filter" => Value::Bytes(target.to_bytes().to_vec())
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(extract_total(&result), 1);
    }

    #[tokio::test]
    async fn test_sqlite_include_entities() {
        let (indexes, cs, li, handler) = setup_sqlite();
        put_entity_sqlite(&cs, &li, &indexes, "users/alice", "app/user", "alice");

        let ctx = make_find_ctx(entity_ecf::cbor_map! {
            "type_filter" => entity_ecf::text("app/user"),
            "include_entities" => entity_ecf::bool_val(true)
        });
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_ENVELOPE);
        let val: ciborium::Value = ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let has_included = map.iter().any(|(k, _)| k.as_text() == Some("included"));
        assert!(has_included, "envelope should contain included entities");
    }
}
