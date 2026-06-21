//! system/tree handler: get, put, snapshot, diff, merge, extract.
//!
//! Per spec §6.3: the tree handler manages entity storage through
//! the content store (Hash → Entity) and location index (Path → Hash).
//!
//! Operations:
//! - `get`: retrieve an entity by path (or listing for prefix)
//! - `put`: store/remove an entity at a path
//! - `snapshot`: capture all bindings under a prefix (returns trie root)
//! - `diff`: compare two snapshots
//! - `merge`: apply source snapshot bindings into the live tree
//! - `extract`: build an envelope with snapshot + referenced entities

pub mod root_tracker;
pub mod trie;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_entity::{Entity, TYPE_DELETION_MARKER};
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult,
    STATUS_BAD_REQUEST, STATUS_CONFLICT, STATUS_FORBIDDEN, STATUS_MULTI_STATUS, STATUS_NOT_FOUND,
    STATUS_NOT_SUPPORTED,
};
use entity_hash::Hash;
use entity_store::{CascadeResult, CasError, ContentStore, ExecutionContext, LocationEntry, LocationIndex};
use thiserror::Error;

/// The tree handler implementing get, put, snapshot, diff, merge, extract.
pub struct TreeHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
}

impl TreeHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/tree", local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
        }
    }

    /// Build an ExecutionContext from a HandlerContext (SYSTEM-COMPOSITION §1.4).
    fn build_execution_context(ctx: &HandlerContext) -> ExecutionContext {
        // Record bare handler pattern (e.g., "system/tree") not absolute
        // (e.g., "/{peerID}/system/tree") — matches manifest and interop convention (W7).
        let bare_pattern = entity_entity::EntityUri::strip_peer_prefix(&ctx.pattern);
        ExecutionContext {
            // Immutable through cascade
            chain_id: ctx.bounds.as_ref().and_then(|b| b.chain_id.clone()),
            parent_chain_id: ctx.bounds.as_ref().and_then(|b| b.parent_chain_id.clone()),
            author: ctx.author,
            caller_capability: ctx.capability_hash,
            request_id: Some(ctx.request_id.clone()),
            // Per-write fields (tree handler is caller-authorized: capability = caller's)
            capability: ctx.capability_hash,
            handler_grant: ctx.handler_grant_hash,
            handler_pattern: Some(bare_pattern.to_string()),
            operation: Some(ctx.operation.clone()),
            // Managed by emit pathway (initial: depth 0)
            cascade_depth: 0,
            // Extension-contributed (set by clock hook)
            clock: None,
        }
    }

    /// Get an entity by path.
    pub fn get(&self, path: &str) -> Option<Entity> {
        let hash = self.location_index.get(path)?;
        self.content_store.get(&hash)
    }

    /// Look up a tracked trie root for `qualified_prefix` (e.g.
    /// `/{peer}/project/`). The binding at `system/tree/root/{bare_prefix}`
    /// points directly at the trie root node's content hash
    /// (EXTENSION-TREE §3.4.1, direct-binding reading).
    fn lookup_tracked_root(&self, qualified_prefix: &str) -> Option<Hash> {
        let peer_qualifier = format!("/{}/", self.local_peer_id);
        let bare = qualified_prefix.strip_prefix(&peer_qualifier)?;
        let key = bare.trim_end_matches('/');
        let root_path = format!("/{}/system/tree/root/{}", self.local_peer_id, key);
        self.location_index.get(&root_path)
    }

    /// Get an entity by hash.
    pub fn get_by_hash(&self, hash: &Hash) -> Option<Entity> {
        self.content_store.get(hash)
    }

    /// Put an entity at a path. Returns the content hash.
    pub fn put(&self, path: &str, entity: Entity) -> Result<Hash, TreeError> {
        let hash = self
            .content_store
            .put(entity)
            .map_err(|e| TreeError::StoreError(e.to_string()))?;
        self.location_index.set(path, hash);
        Ok(hash)
    }

    /// List entries under a prefix.
    pub fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        self.location_index.list(prefix)
    }

    /// Handle a listing request for the given prefix.
    /// Groups entries by immediate child name, producing a single-level listing.
    pub fn handle_listing(&self, prefix: &str) -> Result<HandlerResult, HandlerError> {
        let entries = self.location_index.list(prefix);

        // Group by immediate child name (matching Go handler.go:192-227)
        struct ChildInfo {
            hash: Option<Hash>,
            has_children: bool,
        }
        let mut children: BTreeMap<String, ChildInfo> = BTreeMap::new();

        for entry in &entries {
            let rel = entry.path.strip_prefix(prefix).unwrap_or(&entry.path);
            if rel.is_empty() {
                continue;
            }
            if let Some(slash_idx) = rel.find('/') {
                // Nested path → parent directory has children
                let name = &rel[..slash_idx];
                children
                    .entry(name.to_string())
                    .or_insert(ChildInfo {
                        hash: None,
                        has_children: false,
                    })
                    .has_children = true;
            } else {
                // Direct child
                let info = children
                    .entry(rel.to_string())
                    .or_insert(ChildInfo {
                        hash: None,
                        has_children: false,
                    });
                info.hash = Some(entry.hash);
            }
        }

        // V7 §1.2a + §6.3 / v7.72 §9.5a CORE-TREE-DELETE-1: a path whose direct
        // binding is a `system/deletion-marker` is suppressed from listings.
        // A marker-bound leaf with no nested children drops entirely; one that
        // still has nested descendants stays as a directory-only entry (its
        // leaf binding is hidden, its children remain visible). Resolving the
        // bound entity and comparing its type is format-agnostic — it works
        // regardless of the peer's home content_hash_format (v7.70).
        for info in children.values_mut() {
            if let Some(h) = info.hash {
                if self
                    .content_store
                    .get(&h)
                    .is_some_and(|e| e.entity_type == TYPE_DELETION_MARKER)
                {
                    info.hash = None;
                }
            }
        }
        children.retain(|_name, info| info.hash.is_some() || info.has_children);

        let count = children.len();

        // Build entries map: {name: {hash: bytes|null, has_children: bool}}
        let entry_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = children
            .iter()
            .map(|(name, info)| {
                let hash_val = match info.hash {
                    Some(h) => entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                    None => entity_ecf::Value::Null,
                };
                let entry_map = entity_ecf::Value::Map(vec![
                    (entity_ecf::text("has_children"), entity_ecf::bool_val(info.has_children)),
                    (entity_ecf::text("hash"), hash_val),
                ]);
                (entity_ecf::text(name), entry_map)
            })
            .collect();

        let listing_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("count"), entity_ecf::integer(count as i64)),
            (
                entity_ecf::text("entries"),
                entity_ecf::Value::Map(entry_pairs),
            ),
            (entity_ecf::text("offset"), entity_ecf::integer(0)),
            (entity_ecf::text("path"), entity_ecf::text(prefix)),
        ]));

        let listing_entity =
            Entity::new(entity_types::TYPE_TREE_LISTING, listing_data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(listing_entity))
    }

    /// Check if a path exists.
    pub fn has(&self, path: &str) -> bool {
        self.location_index.has(path)
    }

    /// Remove a path. Returns the removed entity if it existed.
    pub fn remove(&self, path: &str) -> Option<Entity> {
        let hash = self.location_index.remove(path)?;
        self.content_store.get(&hash)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Decode params data from ctx.params (pre-extracted by dispatch layer).
fn decode_params(ctx: &HandlerContext) -> Option<ciborium::Value> {
    ciborium::from_reader(ctx.params.data.as_slice()).ok()
}

/// Get a string field from a CBOR map value.
/// Get a value by key from a CBOR map.
fn cbor_map_get<'a>(map: &'a [(ciborium::Value, ciborium::Value)], key: &str) -> Option<&'a ciborium::Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn map_get_text(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<String> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_text().map(|s| s.to_string()))
}

/// Get a bool field from a CBOR map value.
fn map_get_bool(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<bool> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_bool())
}

/// Get a bytes field from a CBOR map value.
fn map_get_bytes<'a>(map: &'a [(ciborium::Value, ciborium::Value)], key: &str) -> Option<&'a [u8]> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_bytes())
        .map(|v| v.as_slice())
}

/// Get an array field from a CBOR map value.
fn map_get_array<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a [ciborium::Value]> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_array())
        .map(|a| a.as_slice())
}

/// Validate that a non-empty prefix ends with "/".
fn validate_prefix(prefix: &str) -> bool {
    prefix.is_empty() || prefix.ends_with('/')
}

/// Remap a path from source_prefix to target_prefix.
/// Build a system/protocol/error entity.
fn error_entity(code: &str, message: &str) -> Result<Entity, HandlerError> {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    Entity::new(entity_types::TYPE_ERROR, data)
        .map_err(|e| HandlerError::Internal(e.to_string()))
}

/// Build a HandlerResult with an error status.
fn error_result(status: u32, code: &str, message: &str) -> Result<HandlerResult, HandlerError> {
    Ok(HandlerResult::error(status, error_entity(code, message)?))
}

/// First illegal control byte in a tree path, if any (V7 §1.4 / v7.72 §9.5a
/// CORE-TREE-PATH-FLEX-1). §1.4 mandates rejecting null bytes; the cohort floor
/// rejects the full C0 control range (`0x00`–`0x1F`) plus DEL (`0x7F`), matching
/// Go's `ValidatePathChars`, so a path one peer binds is bindable on every peer
/// sharing the tree. Operates on the UTF-8 bytes — format-agnostic. (Multi-byte
/// UTF-8 continuation bytes are ≥ `0x80`, so legitimate Unicode segments pass.)
fn first_illegal_path_byte(path: &str) -> Option<u8> {
    path.bytes().find(|&b| b < 0x20 || b == 0x7F)
}

// (Tree snapshot read removed — PROPOSAL-REVERT-TREE-SNAPSHOT-READ.
// Trie traversal logic will move to the transaction handler.
// Snapshot reads are handled by domain handlers (transaction, revision)
// that have prefix context for correct capability checking.)

fn build_partial_result(cr: CascadeResult) -> HandlerResult {
    use entity_ecf::{text, bool_val, Value};
    let halted_entries: Vec<Value> = cr.consumers_halted.iter().map(|h| {
        Value::Map(vec![
            (text("name"), text(&h.consumer_name)),
            (text("error"), Value::Map(vec![
                (text("code"), text(&h.error_message)),
                (text("status"), Value::Integer(h.error_code.into())),
            ])),
        ])
    }).collect();
    let data = entity_ecf::to_ecf(&Value::Map(vec![
        (text("binding_committed"), bool_val(cr.binding_committed)),
        (text("cascade_depth"), Value::Integer(cr.cascade_depth.into())),
        (text("consumers_completed"), Value::Array(
            cr.consumers_completed.iter().map(|s| text(s)).collect(),
        )),
        (text("consumers_halted"), Value::Array(halted_entries)),
        (text("consumers_skipped"), Value::Array(
            cr.consumers_skipped.iter().map(|s| text(s)).collect(),
        )),
    ]));
    let entity = Entity::new(entity_types::TYPE_TREE_PARTIAL_RESULT, data)
        .expect("partial-result entity construction cannot fail");
    HandlerResult::error(STATUS_MULTI_STATUS, entity)
}

/// Decode an inline entity from CBOR {type, data} or raw bytes.
fn decode_entity_from_cbor(raw: &[u8]) -> Result<Entity, String> {
    let value: ciborium::Value =
        ciborium::from_reader(raw).map_err(|e| format!("cbor decode: {}", e))?;
    let map = value
        .as_map()
        .ok_or_else(|| "entity must be a CBOR map".to_string())?;

    let mut entity_type = None;
    let mut entity_data = None;

    for (k, v) in map {
        match k.as_text() {
            Some("type") => entity_type = v.as_text().map(|s| s.to_string()),
            Some("data") => {
                // data is raw CBOR — re-encode it
                let mut buf = Vec::new();
                ciborium::into_writer(v, &mut buf)
                    .map_err(|e| format!("re-encode data: {}", e))?;
                entity_data = Some(buf);
            }
            _ => {}
        }
    }

    let etype = entity_type.ok_or_else(|| "missing 'type' field".to_string())?;
    let edata = entity_data.ok_or_else(|| "missing 'data' field".to_string())?;

    Entity::new(&etype, edata).map_err(|e| format!("entity new: {}", e))
}

/// Decode bindings from a snapshot entity's data.
///
/// Supports the trie-based format `{root}` (I3 amendment: prefix removed),
/// the legacy `{prefix, root}` format, and the legacy flat `{prefix, bindings}` format.
fn decode_snapshot_bindings_with_store(
    data: &[u8],
    store: &dyn ContentStore,
) -> Option<BTreeMap<String, Hash>> {
    let value: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = value.as_map()?;

    // Try trie-based format: {root} (or legacy {prefix, root})
    let root_entry = map.iter().find(|(k, _)| k.as_text() == Some("root"));
    if let Some((_, root_val)) = root_entry {
        if let Some(root_bytes) = root_val.as_bytes() {
            if let Ok(root_hash) = Hash::from_bytes(root_bytes) {
                return Some(trie::collect_all_bindings(store, root_hash, ""));
            }
        }
    }

    // Fall back to legacy flat format: {prefix, bindings}
    let bindings_entry = map.iter().find(|(k, _)| k.as_text() == Some("bindings"));
    if let Some((_, bindings_val)) = bindings_entry {
        if let Some(bindings_map) = bindings_val.as_map() {
            let mut result = BTreeMap::new();
            for (k, v) in bindings_map {
                let path = k.as_text()?;
                let hash_bytes = v.as_bytes()?;
                let hash = Hash::from_bytes(hash_bytes).ok()?;
                result.insert(path.to_string(), hash);
            }
            return Some(result);
        }
    }

    None
}

// build_snapshot_entity removed — snapshots now use trie-based {root} format (I3 amendment).

// ---------------------------------------------------------------------------
// Handler trait implementation
// ---------------------------------------------------------------------------

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for TreeHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "get" => self.handle_get(ctx),
            "put" => self.handle_put(ctx),
            "snapshot" => self.handle_snapshot(ctx),
            "diff" => self.handle_diff(ctx),
            "merge" => self.handle_merge(ctx),
            "extract" => self.handle_extract(ctx),
            "create" | "destroy" => error_result(
                STATUS_NOT_SUPPORTED,
                "not_implemented",
                &format!("{} is not yet implemented", ctx.operation),
            ),
            _ => error_result(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown operation: {}", ctx.operation),
            ),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "tree"
    }

    fn operations(&self) -> &[&str] {
        &["get", "put", "snapshot", "diff", "merge", "extract", "create", "destroy"]
    }
}

// ---------------------------------------------------------------------------
// Operation implementations
// ---------------------------------------------------------------------------

impl TreeHandler {
    fn handle_get(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let target_path = if let Some(ref rt) = ctx.resource_target {
            if let Some(first) = rt.targets.first() {
                first.clone()
            } else if ctx.suffix.is_empty() {
                ctx.pattern.clone()
            } else {
                format!("{}{}", ctx.pattern, ctx.suffix)
            }
        } else if ctx.suffix.is_empty() {
            ctx.pattern.clone()
        } else {
            format!("{}{}", ctx.pattern, ctx.suffix)
        };

        // Trailing slash or empty path → listing
        if target_path.is_empty() || target_path.ends_with('/') {
            tracing::debug!(path = %target_path, "tree get: listing");
            return self.handle_listing(&target_path);
        }

        match self.get(&target_path) {
            Some(entity) => {
                tracing::debug!(
                    path = %target_path,
                    entity_type = %entity.entity_type,
                    hash = %entity.content_hash,
                    "tree get: found"
                );
                Ok(HandlerResult::ok(entity))
            }
            None => {
                tracing::debug!(path = %target_path, "tree get: not found");
                error_result(
                    STATUS_NOT_FOUND,
                    "not_found",
                    &format!("path not found: {}", target_path),
                )
            }
        }
    }

    fn handle_put(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // Path from resource_target.targets[0]
        let path = ctx
            .resource_target
            .as_ref()
            .and_then(|rt| rt.targets.first().cloned())
            .ok_or_else(|| HandlerError::InvalidParams("resource target path is required".into()))?;

        if path.is_empty() {
            return error_result(
                STATUS_BAD_REQUEST,
                "invalid_params",
                "resource target path is required",
            );
        }

        // V7 §1.4 / v7.72 §9.5a CORE-TREE-PATH-FLEX-1: reject control bytes in
        // the bind path before any binding. The resource-target path bypasses
        // URI canonicalization (which already rejects leading-slash / ./ / ../
        // / empty segments), so this is the surface where a NUL would slip
        // through to a binding.
        if let Some(bad) = first_illegal_path_byte(&path) {
            return error_result(
                STATUS_BAD_REQUEST,
                "invalid_path",
                &format!("path contains illegal control byte {bad:#04x} (V7 §1.4)"),
            );
        }

        let params = decode_params(ctx);

        // Check if entity field is present
        let entity_value = params.as_ref().and_then(|p| {
            let map = p.as_map()?;
            map.iter()
                .find(|(k, _)| k.as_text() == Some("entity"))
                .map(|(_, v)| v)
        });

        // Decode optional expected_hash (ENTITY-CORE-PROTOCOL §3.9).
        let expected_hash = match params.as_ref().and_then(|p| {
            let map = p.as_map()?;
            map.iter()
                .find(|(k, _)| k.as_text() == Some("expected_hash"))
                .map(|(_, v)| v)
        }) {
            None => None,
            Some(v) if v.is_null() => None,
            Some(v) => match v.as_bytes() {
                Some(bytes) => Some(Hash::from_bytes(bytes).map_err(|e| {
                    HandlerError::InvalidParams(format!("expected_hash: {}", e))
                })?),
                None => {
                    return error_result(
                        STATUS_BAD_REQUEST,
                        "invalid_params",
                        "expected_hash must be bytes",
                    );
                }
            },
        };

        let is_remove = match entity_value {
            None => true,
            Some(v) if v.is_null() => true,
            Some(v) if v.as_bytes().is_some_and(|b| b.is_empty()) => true,
            _ => false,
        };

        if is_remove {
            tracing::debug!(path = %path, "tree put: removing binding");
            let emit_ctx = Self::build_execution_context(ctx);
            // V7 §3.9 v7.50: zero expected_hash on remove means "expect absent"
            // — an idempotent no-op when the path is already unbound, else 409.
            // The spec ("applies to both write and remove") makes the zero-hash
            // case symmetric with CAS-create on write.
            if let Some(expected) = expected_hash {
                if expected.is_zero() {
                    match self.location_index.get(&path) {
                        None => {
                            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                                entity_ecf::text("removed"),
                                entity_ecf::bool_val(false),
                            )]));
                            let result = Entity::new(entity_types::TYPE_TREE_PUT_RESULT, data)
                                .map_err(|e| HandlerError::Internal(e.to_string()))?;
                            return Ok(HandlerResult::ok(result));
                        }
                        Some(actual) => {
                            return error_result(
                                STATUS_CONFLICT,
                                "hash_mismatch",
                                &format!("expected_hash zero (expect absent) but binding present at {}: actual {}", path, actual),
                            );
                        }
                    }
                }
            }
            let outcome: Result<(Option<Hash>, CascadeResult), CasError> = match expected_hash {
                Some(expected) => self
                    .location_index
                    .compare_and_remove_with_context(&path, expected, emit_ctx)
                    .map(|(h, c)| (Some(h), c)),
                None => {
                    let (removed, cascade) = self.location_index.remove_with_context(&path, emit_ctx);
                    Ok((removed, cascade))
                }
            };

            match outcome {
                Ok((Some(old_hash), cascade)) => {
                    tracing::debug!(path = %path, old_hash = %old_hash, "tree put: binding removed");
                    if !cascade.is_complete() {
                        return Ok(build_partial_result(cascade));
                    }
                    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                        entity_ecf::text("removed"),
                        entity_ecf::bool_val(true),
                    )]));
                    let result = Entity::new(entity_types::TYPE_TREE_PUT_RESULT, data)
                        .map_err(|e| HandlerError::Internal(e.to_string()))?;
                    Ok(HandlerResult::ok(result))
                }
                Ok((None, _)) => {
                    tracing::debug!(path = %path, "tree put: path not bound for removal");
                    error_result(
                        STATUS_NOT_FOUND,
                        "not_found",
                        &format!("path not bound: {}", path),
                    )
                }
                Err(CasError::NotFound) => error_result(
                    STATUS_CONFLICT,
                    "hash_mismatch",
                    &format!("no binding at {} for expected_hash", path),
                ),
                Err(CasError::Mismatch(actual)) => error_result(
                    STATUS_CONFLICT,
                    "hash_mismatch",
                    &format!("expected_hash mismatch at {}: actual {}", path, actual),
                ),
            }
        } else {
            // Store entity
            let entity_bytes = entity_value.unwrap();

            // Re-encode the CBOR value to bytes for decode_entity_from_cbor
            let mut raw = Vec::new();
            ciborium::into_writer(entity_bytes, &mut raw)
                .map_err(|e| HandlerError::Internal(format!("encode entity bytes: {}", e)))?;

            let entity = decode_entity_from_cbor(&raw)
                .map_err(|e| HandlerError::InvalidParams(format!("invalid_entity: {}", e)))?;

            // Validate hash
            entity
                .validate()
                .map_err(|e| HandlerError::InvalidParams(format!("invalid_entity: {}", e)))?;

            // Store and bind
            let stored_hash = self
                .content_store
                .put(entity.clone())
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            let emit_ctx = Self::build_execution_context(ctx);

            let cascade = if let Some(expected) = expected_hash {
                // V7 §3.9 v7.50: zero expected_hash means CAS-create — succeed
                // only if the path is currently unbound; non-zero retains the
                // existing compare-and-swap semantics.
                let cas_result = if expected.is_zero() {
                    self.location_index
                        .compare_and_create_with_context(&path, stored_hash, emit_ctx)
                } else {
                    self.location_index.compare_and_swap_with_context(
                        &path,
                        expected,
                        stored_hash,
                        emit_ctx,
                    )
                };
                match cas_result {
                    Ok(c) => c,
                    Err(CasError::NotFound) => {
                        return error_result(
                            STATUS_CONFLICT,
                            "hash_mismatch",
                            &format!("no binding at {} for expected_hash", path),
                        );
                    }
                    Err(CasError::Mismatch(actual)) => {
                        return error_result(
                            STATUS_CONFLICT,
                            "hash_mismatch",
                            &format!("expected_hash mismatch at {}: actual {}", path, actual),
                        );
                    }
                }
            } else {
                self.location_index.set_with_context(&path, stored_hash, emit_ctx)
            };

            if !cascade.is_complete() {
                return Ok(build_partial_result(cascade));
            }

            tracing::debug!(
                path = %path,
                entity_type = %entity.entity_type,
                hash = %stored_hash,
                "tree put: stored"
            );

            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("content_hash"),
                entity_ecf::Value::Bytes(stored_hash.to_bytes().to_vec()),
            )]));
            let result = Entity::new(entity_types::TYPE_TREE_PUT_RESULT, data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            Ok(HandlerResult::ok(result))
        }
    }

    fn handle_snapshot(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_params(ctx);

        // V7 §3.2: prefer resource_target (dispatch-layer auth covers it).
        // Sanctioned fallback to params.prefix carries a handler-side auth
        // obligation — see the explicit check below.
        let (prefix, from_params) = match ctx
            .resource_target
            .as_ref()
            .and_then(|rt| rt.targets.first().cloned())
        {
            Some(p) => (p, false),
            None => match params.as_ref().and_then(|p| {
                let map = p.as_map()?;
                map_get_text(map, "prefix")
            }) {
                Some(p) => (p, true),
                None => (String::new(), false),
            },
        };

        if !validate_prefix(&prefix) {
            return error_result(
                STATUS_BAD_REQUEST,
                "invalid_prefix",
                "non-empty prefix must end with '/'",
            );
        }

        // V7 §3.2 confused-deputy obligation: when the path came from
        // params (not resource_target), the dispatch-layer capability check
        // did not see this path. The handler MUST perform its own auth
        // check, otherwise a caller authorized for one prefix could
        // snapshot a different one. PROPOSAL-CROSS-IMPL-STANDARDIZATION-
        // CATCHUP §3.
        if from_params {
            if let Some(ref cap) = ctx.caller_capability {
                if !entity_capability::check_permission(
                    "snapshot",
                    &format!("/{}/system/tree", self.local_peer_id),
                    &self.local_peer_id,
                    Some(&entity_capability::ResourceTarget {
                        targets: vec![prefix.clone()],
                        exclude: vec![],
                    }),
                    cap,
                    &self.local_peer_id,
                ) {
                    return error_result(
                        STATUS_FORBIDDEN,
                        "access_denied",
                        "insufficient capability for prefix supplied in params",
                    );
                }
            }
        }

        // Fast path: EXTENSION-TREE §3.4 — if an incremental trie root is
        // being maintained for this prefix, return it directly.
        if let Some(tracked) = self.lookup_tracked_root(&prefix) {
            tracing::debug!(prefix = %prefix, root = %tracked, "tree snapshot: tracked root");
            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("root"),
                entity_ecf::Value::Bytes(tracked.to_bytes().to_vec()),
            )]));
            let snapshot = Entity::new(entity_types::TYPE_TREE_SNAPSHOT, data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            return Ok(HandlerResult::ok(snapshot));
        }

        // Collect all bindings under prefix
        let entries = self.location_index.list(&prefix);
        let mut bindings = BTreeMap::new();
        for entry in &entries {
            let rel = entry.path.strip_prefix(&prefix).unwrap_or(&entry.path);
            bindings.insert(rel.to_string(), entry.hash);
        }

        tracing::debug!(prefix = %prefix, bindings = bindings.len(), "tree snapshot: building trie");

        // Build content-addressed trie per EXTENSION-TREE v3.2 §3.3
        let root_hash = trie::build_trie(self.content_store.as_ref(), &bindings)
            .map_err(|e| HandlerError::Internal(format!("trie build: {}", e)))?;

        tracing::debug!(prefix = %prefix, root = %root_hash, bindings = bindings.len(), "tree snapshot: built");

        // Return {root} per spec (I3 amendment: prefix removed from snapshot)
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("root"),
                entity_ecf::Value::Bytes(root_hash.to_bytes().to_vec()),
            ),
        ]));
        let snapshot = Entity::new(entity_types::TYPE_TREE_SNAPSHOT, data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(snapshot))
    }

    fn handle_diff(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_params(ctx).ok_or_else(|| {
            HandlerError::InvalidParams("params required for diff".into())
        })?;
        let params_map = params
            .as_map()
            .ok_or_else(|| HandlerError::InvalidParams("params must be a map".into()))?;

        let base_bytes = map_get_bytes(params_map, "base")
            .ok_or_else(|| HandlerError::InvalidParams("base hash required".into()))?;
        let target_bytes = map_get_bytes(params_map, "target")
            .ok_or_else(|| HandlerError::InvalidParams("target hash required".into()))?;

        let base_hash =
            Hash::from_bytes(base_bytes).map_err(|e| HandlerError::InvalidParams(e.to_string()))?;
        let target_hash = Hash::from_bytes(target_bytes)
            .map_err(|e| HandlerError::InvalidParams(e.to_string()))?;

        // Resolve snapshots (content store first, then included)
        let base_entity = match self
            .content_store
            .get(&base_hash)
            .or_else(|| ctx.included.get(&base_hash).cloned())
        {
            Some(e) => e,
            None => return error_result(STATUS_NOT_FOUND, "snapshot_not_found", "base snapshot not found"),
        };
        let target_entity = match self
            .content_store
            .get(&target_hash)
            .or_else(|| ctx.included.get(&target_hash).cloned())
        {
            Some(e) => e,
            None => return error_result(STATUS_NOT_FOUND, "snapshot_not_found", "target snapshot not found"),
        };

        let base_bindings = decode_snapshot_bindings_with_store(&base_entity.data, self.content_store.as_ref()).ok_or_else(|| {
            HandlerError::InvalidParams("failed to decode base snapshot bindings".into())
        })?;
        let target_bindings =
            decode_snapshot_bindings_with_store(&target_entity.data, self.content_store.as_ref()).ok_or_else(|| {
                HandlerError::InvalidParams("failed to decode target snapshot bindings".into())
            })?;

        // Compare
        let mut added: BTreeMap<String, Hash> = BTreeMap::new();
        let mut removed: BTreeMap<String, Hash> = BTreeMap::new();
        let mut changed: BTreeMap<String, (Hash, Hash)> = BTreeMap::new();
        let mut unchanged: u64 = 0;

        // Check target for added/changed
        for (path, target_h) in &target_bindings {
            match base_bindings.get(path) {
                None => {
                    added.insert(path.clone(), *target_h);
                }
                Some(base_h) if base_h != target_h => {
                    changed.insert(path.clone(), (*base_h, *target_h));
                }
                Some(_) => {
                    unchanged += 1;
                }
            }
        }
        // Check base for removed
        for (path, base_h) in &base_bindings {
            if !target_bindings.contains_key(path) {
                removed.insert(path.clone(), *base_h);
            }
        }

        // Build diff entity
        let added_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = added
            .iter()
            .map(|(p, h)| {
                (
                    entity_ecf::text(p),
                    entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                )
            })
            .collect();

        let changed_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = changed
            .iter()
            .map(|(p, (bh, th))| {
                (
                    entity_ecf::text(p),
                    entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("base_hash"),
                            entity_ecf::Value::Bytes(bh.to_bytes().to_vec()),
                        ),
                        (
                            entity_ecf::text("target_hash"),
                            entity_ecf::Value::Bytes(th.to_bytes().to_vec()),
                        ),
                    ]),
                )
            })
            .collect();

        let removed_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = removed
            .iter()
            .map(|(p, h)| {
                (
                    entity_ecf::text(p),
                    entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                )
            })
            .collect();

        let diff_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("added"),
                entity_ecf::Value::Map(added_pairs),
            ),
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(base_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("changed"),
                entity_ecf::Value::Map(changed_pairs),
            ),
            (
                entity_ecf::text("removed"),
                entity_ecf::Value::Map(removed_pairs),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(target_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("unchanged"),
                entity_ecf::integer(unchanged as i64),
            ),
        ]));

        let diff_entity = Entity::new(entity_types::TYPE_TREE_DIFF, diff_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(diff_entity))
    }

    fn handle_merge(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_params(ctx).ok_or_else(|| {
            HandlerError::InvalidParams("params required for merge".into())
        })?;
        let params_map = params
            .as_map()
            .ok_or_else(|| HandlerError::InvalidParams("params must be a map".into()))?;

        // Resolve source snapshot hash: either from `source` (direct hash) or
        // from `source_envelope` (inline envelope entity from continuation chains).
        // source_envelope accepts the extract result directly — the merge handler
        // ingests the envelope's entities and uses the root snapshot as source.
        let source_hash = if let Some(source_bytes) = map_get_bytes(params_map, "source") {
            let h = Hash::from_bytes(source_bytes)
                .map_err(|e| HandlerError::InvalidParams(e.to_string()))?;
            // Skip zero hashes — fall through to source_envelope if present.
            if h.is_zero() { None } else { Some(h) }
        } else {
            None
        };
        let source_hash = if let Some(h) = source_hash {
            h
        } else if let Some(env_val) = cbor_map_get(params_map, "source_envelope") {
            // source_envelope: inline entity wrapping an envelope, or raw envelope.
            // Per TREE §5.2: handler ingests included entities and uses root as source.
            // Entity data is re-encoded via ciborium round-trip (same approach as
            // wire::decode_entity — ciborium preserves CBOR byte fidelity).
            let env_map = env_val.as_map().ok_or_else(|| {
                HandlerError::InvalidParams("source_envelope must be a map".into())
            })?;

            // Unwrap entity wrapper if present (from continuation inject mode)
            let has_type = env_map.iter().any(|(k, _)| k.as_text() == Some("type"));
            let has_data = env_map.iter().any(|(k, _)| k.as_text() == Some("data"));
            let envelope_map = if has_type && has_data {
                let data_val = cbor_map_get(env_map, "data").ok_or_else(|| {
                    HandlerError::InvalidParams("source_envelope entity missing data".into())
                })?;
                data_val.as_map().ok_or_else(|| {
                    HandlerError::InvalidParams("source_envelope data must be a map".into())
                })?
            } else {
                env_map
            };

            // Ingest included entities into content store
            if let Some(included_val) = cbor_map_get(envelope_map, "included") {
                if let Some(included_map) = included_val.as_map() {
                    for (_key, val) in included_map {
                        if let Some(ent_map) = val.as_map() {
                            let ent_type = cbor_map_get(ent_map, "type")
                                .and_then(|v| v.as_text().map(String::from))
                                .unwrap_or_default();
                            // Use ciborium round-trip for data (preserves CBOR fidelity,
                            // same approach as wire::decode_entity)
                            let ent_data = if let Some(d) = cbor_map_get(ent_map, "data") {
                                let mut buf = Vec::new();
                                ciborium::into_writer(d, &mut buf).ok();
                                buf
                            } else {
                                Vec::new()
                            };
                            if !ent_type.is_empty() && !ent_data.is_empty() {
                                if let Ok(entity) = Entity::new(&ent_type, ent_data) {
                                    let _ = self.content_store.put(entity);
                                }
                            }
                        }
                    }
                }
            }

            // Extract and store the root (snapshot) entity
            let root_val = cbor_map_get(envelope_map, "root").ok_or_else(|| {
                HandlerError::InvalidParams("source_envelope missing root".into())
            })?;
            let root_map = root_val.as_map().ok_or_else(|| {
                HandlerError::InvalidParams("source_envelope root must be a map".into())
            })?;
            let root_type = cbor_map_get(root_map, "type")
                .and_then(|v| v.as_text().map(String::from))
                .unwrap_or_default();
            let root_data = if let Some(d) = cbor_map_get(root_map, "data") {
                let mut buf = Vec::new();
                ciborium::into_writer(d, &mut buf).ok();
                buf
            } else {
                Vec::new()
            };
            let root_entity = Entity::new(&root_type, root_data)
                .map_err(|e| HandlerError::Internal(format!("build root entity: {}", e)))?;
            let root_hash = self.content_store.put(root_entity)
                .map_err(|e| HandlerError::Internal(format!("store root entity: {}", e)))?;
            root_hash
        } else {
            return Err(HandlerError::InvalidParams(
                "source snapshot hash or source_envelope required".into(),
            ));
        };

        let strategy = map_get_text(params_map, "strategy")
            .unwrap_or_else(|| "no-overwrite".to_string());

        // Validate strategy
        match strategy.as_str() {
            "no-overwrite" | "source-wins" | "target-wins" => {}
            _ => {
                return error_result(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    &format!("invalid merge strategy: {}", strategy),
                );
            }
        }

        let source_prefix = map_get_text(params_map, "source_prefix").unwrap_or_default();
        let target_prefix = map_get_text(params_map, "target_prefix").unwrap_or_default();
        let dry_run = map_get_bool(params_map, "dry_run").unwrap_or(false);

        // Extract peer-id namespace from the handler pattern (e.g., "/{peer_id}/system/tree").
        // The pattern is absolute — first segment after "/" is the peer_id.
        // Only qualifies bare prefixes when the namespace is actually a peer ID,
        // not when running in tests with unqualified patterns like "system/tree".
        let pattern_path = ctx.pattern.strip_prefix('/').unwrap_or(&ctx.pattern);
        let namespace = pattern_path.split('/').next().unwrap_or("");
        let namespace_is_peer_id = entity_entity::EntityUri::is_peer_id(namespace);

        // Resolve source snapshot (content store — already ingested above if from envelope)
        let source_entity = match self
            .content_store
            .get(&source_hash)
            .or_else(|| ctx.included.get(&source_hash).cloned())
        {
            Some(e) => e,
            None => return error_result(STATUS_NOT_FOUND, "snapshot_not_found", "source snapshot not found"),
        };

        let source_bindings =
            decode_snapshot_bindings_with_store(&source_entity.data, self.content_store.as_ref()).ok_or_else(|| {
                HandlerError::InvalidParams("failed to decode source snapshot".into())
            })?;

        // I3 amendment: prefix removed from snapshot entity.
        // Use source_prefix/target_prefix from merge params to compute target path.
        // Qualify bare prefixes with the local peer namespace when the handler is
        // registered under a peer-id-qualified pattern. Bare paths from continuation
        // params need the peer ID prefix that Go's NamespacedIndex would normally provide.
        let qualify = |p: &str| -> String {
            if p.is_empty() || !namespace_is_peer_id {
                return p.to_string();
            }
            // Already absolute or URI — pass through
            if p.starts_with('/') || p.starts_with("entity://") {
                return p.to_string();
            }
            format!("/{}/{}", namespace, p)
        };

        let apply_prefix = if !target_prefix.is_empty() {
            qualify(&target_prefix)
        } else if !source_prefix.is_empty() {
            qualify(&source_prefix)
        } else {
            // EXTENSION-TREE §5.2: "When neither [source_prefix nor
            // target_prefix] is provided, bindings use relative paths as-is."
            // The validator's `merge_dry_run_no_apply` WARN (Applied=1 vs 0)
            // stems from this spec'd behavior — TreeMerge with no prefix
            // can't recover the snapshot's original prefix, so target_path
            // = bare rel_path which never matches the qualified live entry.
            // Matches Go's behavior; cross-impl WARN is observation-level,
            // not a spec violation.
            String::new()
        };

        let mut applied: u64 = 0;
        let mut skipped: u64 = 0;
        let mut conflicts: BTreeMap<String, (Hash, Hash, String)> = BTreeMap::new();
        let merge_emit_ctx = Self::build_execution_context(ctx);

        for (rel_path, source_h) in &source_bindings {
            let target_path = format!("{}{}", apply_prefix, rel_path);

            let existing = self.location_index.get(&target_path);

            match existing {
                None => {
                    if !dry_run {
                        let _cascade = self.location_index.set_with_context(&target_path, *source_h, merge_emit_ctx.clone());
                    }
                    applied += 1;
                }
                Some(existing_h) if existing_h == *source_h => {
                    skipped += 1;
                }
                Some(existing_h) => {
                    match strategy.as_str() {
                        "source-wins" => {
                            if !dry_run {
                                let _cascade = self.location_index.set_with_context(&target_path, *source_h, merge_emit_ctx.clone());
                            }
                            conflicts.insert(
                                target_path,
                                (existing_h, *source_h, "used-incoming".to_string()),
                            );
                            applied += 1;
                        }
                        "target-wins" => {
                            conflicts.insert(
                                target_path,
                                (existing_h, *source_h, "kept-existing".to_string()),
                            );
                            skipped += 1;
                        }
                        _ => {
                            // no-overwrite
                            conflicts.insert(
                                target_path,
                                (existing_h, *source_h, "unresolved".to_string()),
                            );
                            skipped += 1;
                        }
                    }
                }
            }
        }

        // Build merge result
        let conflict_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = conflicts
            .iter()
            .map(|(path, (existing_h, incoming_h, resolution))| {
                (
                    entity_ecf::text(path),
                    entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("existing_hash"),
                            entity_ecf::Value::Bytes(existing_h.to_bytes().to_vec()),
                        ),
                        (
                            entity_ecf::text("incoming_hash"),
                            entity_ecf::Value::Bytes(incoming_h.to_bytes().to_vec()),
                        ),
                        (
                            entity_ecf::text("resolution"),
                            entity_ecf::text(resolution),
                        ),
                    ]),
                )
            })
            .collect();

        let result_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("applied"),
                entity_ecf::integer(applied as i64),
            ),
            (
                entity_ecf::text("conflicts"),
                entity_ecf::Value::Map(conflict_pairs),
            ),
            (
                entity_ecf::text("skipped"),
                entity_ecf::integer(skipped as i64),
            ),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text(&strategy),
            ),
        ]));

        let result_entity = Entity::new(entity_types::TYPE_TREE_MERGE_RESULT, result_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(result_entity))
    }

    fn handle_extract(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let params = decode_params(ctx);

        // Prefix from resource_target (priority) or params. The protocol
        // layer (`core/peer/src/connection.rs`) qualifies resource-target
        // paths via `EntityUri::qualify_path` before they arrive here, so
        // the resource-target branch is already absolute. The `params.prefix`
        // fallback comes through *un-qualified* — we absolutize it here so
        // that bare prefixes (e.g. `foo/`) resolve against the LI's absolute
        // bindings.
        let prefix = ctx
            .resource_target
            .as_ref()
            .and_then(|rt| rt.targets.first().cloned())
            .or_else(|| {
                params.as_ref().and_then(|p| {
                    let map = p.as_map()?;
                    map_get_text(map, "prefix").map(|raw| {
                        entity_entity::EntityUri::qualify_path(&raw, &self.local_peer_id)
                    })
                })
            })
            .unwrap_or_default();

        if !validate_prefix(&prefix) {
            return error_result(
                STATUS_BAD_REQUEST,
                "invalid_prefix",
                "non-empty prefix must end with '/'",
            );
        }

        // Optional paths filter
        let paths_filter: Option<Vec<String>> = params.as_ref().and_then(|p| {
            let map = p.as_map()?;
            let arr = map_get_array(map, "paths")?;
            let paths: Vec<String> = arr.iter().filter_map(|v| v.as_text().map(String::from)).collect();
            if paths.is_empty() { None } else { Some(paths) }
        });

        // Collect bindings
        let bindings: BTreeMap<String, Hash> = if let Some(ref paths) = paths_filter {
            // Look up specific paths
            let mut map = BTreeMap::new();
            for rel_path in paths {
                let full_path = format!("{}{}", prefix, rel_path);
                if let Some(hash) = self.location_index.get(&full_path) {
                    map.insert(rel_path.clone(), hash);
                }
            }
            map
        } else {
            // List all under prefix
            let entries = self.location_index.list(&prefix);
            entries
                .iter()
                .map(|e| {
                    let rel = e.path.strip_prefix(&prefix).unwrap_or(&e.path);
                    (rel.to_string(), e.hash)
                })
                .collect()
        };

        // Build trie and snapshot entity as root
        let root_hash = trie::build_trie(self.content_store.as_ref(), &bindings)
            .map_err(|e| HandlerError::Internal(format!("trie build: {}", e)))?;
        let snap_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("root"),
                entity_ecf::Value::Bytes(root_hash.to_bytes().to_vec()),
            ),
        ]));
        let snapshot = Entity::new(entity_types::TYPE_TREE_SNAPSHOT, snap_data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // Build included map: all referenced entities
        let mut included_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();

        // Include the snapshot itself (with content_hash for Store.Put roundtrip)
        included_pairs.push((
            entity_ecf::Value::Bytes(snapshot.content_hash.to_bytes().to_vec()),
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("content_hash"),
                    entity_ecf::Value::Bytes(snapshot.content_hash.to_bytes().to_vec()),
                ),
                (
                    entity_ecf::text("data"),
                    raw_cbor_value(&snapshot.data),
                ),
                (
                    entity_ecf::text("type"),
                    entity_ecf::text(&snapshot.entity_type),
                ),
            ]),
        ));

        // Include all trie node entities (per TREE §6.2 — MUST include all reachable nodes)
        let trie_hashes = trie::collect_all_hashes(self.content_store.as_ref(), root_hash);
        for h in &trie_hashes {
            // Skip binding hashes (data entities are added below) and the snapshot itself
            if bindings.values().any(|bh| bh == h) || *h == snapshot.content_hash {
                continue;
            }
            if let Some(entity) = self.content_store.get(h) {
                included_pairs.push((
                    entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                    entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("content_hash"),
                            entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                        ),
                        (
                            entity_ecf::text("data"),
                            raw_cbor_value(&entity.data),
                        ),
                        (
                            entity_ecf::text("type"),
                            entity_ecf::text(&entity.entity_type),
                        ),
                    ]),
                ));
            }
        }

        // Include data entities referenced by bindings
        for hash in bindings.values() {
            if let Some(entity) = self.content_store.get(hash) {
                included_pairs.push((
                    entity_ecf::Value::Bytes(hash.to_bytes().to_vec()),
                    entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("content_hash"),
                            entity_ecf::Value::Bytes(hash.to_bytes().to_vec()),
                        ),
                        (
                            entity_ecf::text("data"),
                            raw_cbor_value(&entity.data),
                        ),
                        (
                            entity_ecf::text("type"),
                            entity_ecf::text(&entity.entity_type),
                        ),
                    ]),
                ));
            }
        }

        // Build envelope entity: {included: {...}, root: {content_hash, data, type}}
        let envelope_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("included"),
                entity_ecf::Value::Map(included_pairs),
            ),
            (
                entity_ecf::text("root"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("content_hash"),
                        entity_ecf::Value::Bytes(snapshot.content_hash.to_bytes().to_vec()),
                    ),
                    (
                        entity_ecf::text("data"),
                        raw_cbor_value(&snapshot.data),
                    ),
                    (
                        entity_ecf::text("type"),
                        entity_ecf::text(&snapshot.entity_type),
                    ),
                ]),
            ),
        ]));

        // EXTENSION-TREE §6 + PROPOSAL-CONTINUATION-TRANSFORM-AND-ENVELOPE-AMENDMENTS S3:
        // extract returns `system/envelope` (data bundle), NOT
        // `system/protocol/envelope` (a distinct protocol-message type).
        let envelope_entity =
            Entity::new(entity_types::TYPE_ENVELOPE, envelope_data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult::ok(envelope_entity))
    }
}

/// Parse raw CBOR bytes back into a ciborium::Value for embedding in ECF output.
fn raw_cbor_value(data: &[u8]) -> entity_ecf::Value {
    ciborium::from_reader::<ciborium::Value, _>(data)
        .unwrap_or(entity_ecf::Value::Null)
}

#[derive(Debug, Error)]
pub enum TreeError {
    #[error("store error: {0}")]
    StoreError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_capability::ResourceTarget;
    use entity_handler::STATUS_OK;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id() -> String {
        entity_crypto::Keypair::from_seed([42u8; 32]).peer_id().to_string()
    }

    fn make_tree() -> TreeHandler {
        TreeHandler::new(
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
            test_peer_id(),
        )
    }

    fn make_entity(type_str: &str, data_str: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(data_str));
        Entity::new(type_str, data).unwrap()
    }

    /// Build a HandlerContext for testing tree operations.
    fn make_handler_context(
        operation: &str,
        params_value: Option<entity_ecf::Value>,
        resource_targets: Option<Vec<String>>,
    ) -> HandlerContext {
        // Build params entity from the data value
        let params_data_val = params_value.unwrap_or(entity_ecf::Value::Null);
        let params_data_bytes = entity_ecf::to_ecf(&params_data_val);
        let params_type = format!("system/tree/{}-params", operation);
        let params = Entity::new(&params_type, params_data_bytes).unwrap();

        // Build EXECUTE entity (still needed for ctx.execute)
        let execute_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text(operation)),
            (entity_ecf::text("request_id"), entity_ecf::text("test-req-1")),
            (entity_ecf::text("uri"), entity_ecf::text("system/tree")),
        ]));
        let execute = Entity::new(entity_types::TYPE_EXECUTE, execute_data).unwrap();

        let resource_target = resource_targets.map(|targets| ResourceTarget {
            targets,
            exclude: vec![],
        });

        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            pattern: "system/tree".to_string(),
            suffix: String::new(),
            resource_target,
            author: None,
            session_peer_id: None,
            request_id: "test-req-1".to_string(),
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

    fn decode_cbor(data: &[u8]) -> ciborium::Value {
        ciborium::from_reader(data).unwrap()
    }

    fn cbor_map_get<'a>(
        map: &'a [(ciborium::Value, ciborium::Value)],
        key: &str,
    ) -> &'a ciborium::Value {
        &map.iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .unwrap_or_else(|| panic!("key '{}' not found", key))
            .1
    }

    // -----------------------------------------------------------------------
    // Direct API tests (existing)
    // -----------------------------------------------------------------------

    #[test]
    fn test_put_get() {
        let tree = make_tree();
        let entity = make_entity("test/type", "hello");
        let hash = tree.put("test/path", entity.clone()).unwrap();
        let got = tree.get("test/path").unwrap();
        assert_eq!(got.content_hash, entity.content_hash);
        assert_eq!(got.content_hash, hash);
    }

    #[test]
    fn test_get_missing() {
        let tree = make_tree();
        assert!(tree.get("nonexistent").is_none());
    }

    #[test]
    fn test_get_by_hash() {
        let tree = make_tree();
        let entity = make_entity("test/type", "hello");
        let hash = tree.put("test/path", entity).unwrap();
        assert!(tree.get_by_hash(&hash).is_some());
        assert!(tree.get_by_hash(&Hash::zero()).is_none());
    }

    #[test]
    fn test_has() {
        let tree = make_tree();
        assert!(!tree.has("test/path"));
        tree.put("test/path", make_entity("test", "data")).unwrap();
        assert!(tree.has("test/path"));
    }

    #[test]
    fn test_remove() {
        let tree = make_tree();
        let entity = make_entity("test/type", "hello");
        tree.put("test/path", entity.clone()).unwrap();
        let removed = tree.remove("test/path");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().content_hash, entity.content_hash);
        assert!(!tree.has("test/path"));
    }

    #[test]
    fn test_remove_missing() {
        let tree = make_tree();
        assert!(tree.remove("nonexistent").is_none());
    }

    #[test]
    fn test_list() {
        let tree = make_tree();
        tree.put("system/handler/a", make_entity("test", "a")).unwrap();
        tree.put("system/handler/b", make_entity("test", "b")).unwrap();
        tree.put("system/tree", make_entity("test", "c")).unwrap();

        let entries = tree.list("system/handler/");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "system/handler/a");
        assert_eq!(entries[1].path, "system/handler/b");
    }

    #[test]
    fn test_put_overwrite() {
        let tree = make_tree();
        let e1 = make_entity("test", "first");
        let e2 = make_entity("test", "second");
        tree.put("path", e1).unwrap();
        tree.put("path", e2.clone()).unwrap();
        let got = tree.get("path").unwrap();
        assert_eq!(got.content_hash, e2.content_hash);
    }

    #[test]
    fn test_handler_pattern() {
        let tree = make_tree();
        assert_eq!(tree.pattern(), format!("/{}/system/tree", test_peer_id()));
        assert_eq!(tree.name(), "tree");
        assert_eq!(
            tree.operations(),
            &["get", "put", "snapshot", "diff", "merge", "extract", "create", "destroy"]
        );
    }

    // -----------------------------------------------------------------------
    // Listing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_listing_basic() {
        let tree = make_tree();
        tree.put("local/files/a.txt", make_entity("test", "a")).unwrap();
        tree.put("local/files/b.txt", make_entity("test", "b")).unwrap();

        let result = tree.handle_listing("local/files/").unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.result.entity_type, entity_types::TYPE_TREE_LISTING);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let count = cbor_map_get(map, "count").as_integer().unwrap();
        assert_eq!(i128::from(count), 2);
    }

    #[test]
    fn test_listing_groups_children() {
        let tree = make_tree();
        tree.put("dir/a", make_entity("test", "a")).unwrap();
        tree.put("dir/sub/b", make_entity("test", "b")).unwrap();
        tree.put("dir/sub/c", make_entity("test", "c")).unwrap();

        let result = tree.handle_listing("dir/").unwrap();
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let count = cbor_map_get(map, "count").as_integer().unwrap();
        assert_eq!(i128::from(count), 2);

        let entries = cbor_map_get(map, "entries").as_map().unwrap();

        let a_entry = cbor_map_get(entries, "a").as_map().unwrap();
        let a_hash = cbor_map_get(a_entry, "hash");
        assert!(a_hash.as_bytes().is_some(), "direct child should have hash");

        let sub_entry = cbor_map_get(entries, "sub").as_map().unwrap();
        let sub_hash = cbor_map_get(sub_entry, "hash");
        assert!(sub_hash.is_null(), "directory should have null hash");
        let sub_children = cbor_map_get(sub_entry, "has_children");
        assert_eq!(sub_children.as_bool(), Some(true));
    }

    #[test]
    fn test_listing_empty_prefix() {
        let tree = make_tree();
        let result = tree.handle_listing("nonexistent/").unwrap();
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let count = cbor_map_get(map, "count").as_integer().unwrap();
        assert_eq!(i128::from(count), 0);
    }

    // -----------------------------------------------------------------------
    // Handler dispatch tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_get_entity() {
        let tree = make_tree();
        let entity = make_entity("test/type", "hello");
        tree.put("docs/readme", entity.clone()).unwrap();

        let ctx = make_handler_context("get", None, Some(vec!["docs/readme".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.content_hash, entity.content_hash);
    }

    #[tokio::test]
    async fn test_handler_get_not_found() {
        let tree = make_tree();
        let ctx = make_handler_context("get", None, Some(vec!["missing/path".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_handler_get_listing() {
        let tree = make_tree();
        tree.put("docs/a", make_entity("test", "a")).unwrap();
        let ctx = make_handler_context("get", None, Some(vec!["docs/".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_TREE_LISTING);
    }

    #[tokio::test]
    async fn test_handler_unknown_operation() {
        let tree = make_tree();
        let ctx = make_handler_context("frobnicate", None, None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // PUT operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_put_store_entity() {
        let tree = make_tree();

        // Build an inline entity in params
        let inner = make_entity("test/doc", "my document");
        let inner_data_val: ciborium::Value =
            ciborium::from_reader(inner.data.as_slice()).unwrap();

        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("entity"),
            entity_ecf::Value::Map(vec![
                (entity_ecf::text("data"), inner_data_val),
                (
                    entity_ecf::text("type"),
                    entity_ecf::text(&inner.entity_type),
                ),
            ]),
        )]);

        let ctx = make_handler_context("put", Some(params), Some(vec!["docs/readme".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_TREE_PUT_RESULT);

        // Verify entity was stored
        let stored = tree.get("docs/readme").unwrap();
        assert_eq!(stored.content_hash, inner.content_hash);

        // Verify response contains content_hash
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let hash_bytes = cbor_map_get(map, "content_hash").as_bytes().unwrap();
        let returned_hash = Hash::from_bytes(hash_bytes).unwrap();
        assert_eq!(returned_hash, inner.content_hash);
    }

    #[tokio::test]
    async fn test_handler_put_remove_binding() {
        let tree = make_tree();
        tree.put("docs/readme", make_entity("test", "data")).unwrap();

        // Put with null entity → remove
        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("entity"),
            entity_ecf::Value::Null,
        )]);

        let ctx = make_handler_context("put", Some(params), Some(vec!["docs/readme".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        assert_eq!(cbor_map_get(map, "removed").as_bool(), Some(true));

        // Verify binding is gone
        assert!(!tree.has("docs/readme"));
    }

    #[tokio::test]
    async fn test_handler_put_remove_not_found() {
        let tree = make_tree();

        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("entity"),
            entity_ecf::Value::Null,
        )]);

        let ctx = make_handler_context("put", Some(params), Some(vec!["missing/path".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_handler_put_missing_path() {
        let tree = make_tree();
        let ctx = make_handler_context("put", None, None);
        let result = tree.handle(&ctx).await;
        assert!(result.is_err()); // InvalidParams
    }

    // -----------------------------------------------------------------------
    // PUT expected_hash / CAS tests (ENTITY-CORE-PROTOCOL §3.9)
    // -----------------------------------------------------------------------

    /// Build `put` params for a CAS test: optional inline entity + optional expected_hash.
    fn put_params_with_expected(
        entity: Option<&Entity>,
        expected: Option<Hash>,
    ) -> entity_ecf::Value {
        let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();
        if let Some(e) = entity {
            let inner_data_val: ciborium::Value =
                ciborium::from_reader(e.data.as_slice()).unwrap();
            fields.push((
                entity_ecf::text("entity"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("data"), inner_data_val),
                    (entity_ecf::text("type"), entity_ecf::text(&e.entity_type)),
                ]),
            ));
        } else {
            fields.push((entity_ecf::text("entity"), entity_ecf::Value::Null));
        }
        if let Some(h) = expected {
            fields.push((
                entity_ecf::text("expected_hash"),
                entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
            ));
        }
        entity_ecf::Value::Map(fields)
    }

    #[tokio::test]
    async fn test_handler_put_cas_match_succeeds() {
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        let h1 = tree.put("cas/path", e1.clone()).unwrap();

        let e2 = make_entity("test", "v2");
        let params = put_params_with_expected(Some(&e2), Some(h1));
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/path".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(tree.get("cas/path").unwrap().content_hash, e2.content_hash);
    }

    #[tokio::test]
    async fn test_handler_put_cas_mismatch_returns_409() {
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        tree.put("cas/path", e1).unwrap();

        let wrong = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("wrong")));
        let e2 = make_entity("test", "v2");
        let params = put_params_with_expected(Some(&e2), Some(wrong));
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/path".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        assert_eq!(cbor_map_get(map, "code").as_text(), Some("hash_mismatch"));
    }

    #[tokio::test]
    async fn test_handler_put_cas_missing_binding_returns_409() {
        let tree = make_tree();
        let expected = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("x")));
        let e = make_entity("test", "new");
        let params = put_params_with_expected(Some(&e), Some(expected));
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/missing".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        assert_eq!(cbor_map_get(map, "code").as_text(), Some("hash_mismatch"));
        assert!(!tree.has("cas/missing"));
    }

    #[tokio::test]
    async fn test_handler_put_cas_absent_is_unconditional() {
        // Backward compat: no expected_hash → unconditional put.
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        tree.put("cas/path", e1).unwrap();

        let e2 = make_entity("test", "v2");
        let params = put_params_with_expected(Some(&e2), None);
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/path".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(tree.get("cas/path").unwrap().content_hash, e2.content_hash);
    }

    #[tokio::test]
    async fn test_handler_put_cas_remove_match_succeeds() {
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        let h1 = tree.put("cas/path", e1).unwrap();

        let params = put_params_with_expected(None, Some(h1));
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/path".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert!(!tree.has("cas/path"));
    }

    #[tokio::test]
    async fn test_handler_put_cas_remove_mismatch_returns_409() {
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        tree.put("cas/path", e1).unwrap();

        let wrong = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("wrong")));
        let params = put_params_with_expected(None, Some(wrong));
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/path".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        // Binding still present
        assert!(tree.has("cas/path"));
    }

    #[tokio::test]
    async fn test_handler_put_cas_create_zero_hash_unbound_succeeds() {
        // V7 §3.9 v7.50: expected_hash = zero on an unbound path → CAS-create
        // succeeds and binds the entity.
        let tree = make_tree();
        let e = make_entity("test", "first");
        let params = put_params_with_expected(Some(&e), Some(Hash::zero()));
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/fresh".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(tree.get("cas/fresh").unwrap().content_hash, e.content_hash);
    }

    #[tokio::test]
    async fn test_handler_put_cas_create_zero_hash_bound_returns_409() {
        // V7 §3.9 v7.50: expected_hash = zero on a bound path → 409
        // hash_mismatch (the create precondition is "path is unbound").
        let tree = make_tree();
        let e1 = make_entity("test", "first");
        let h1 = tree.put("cas/taken", e1.clone()).unwrap();

        let e2 = make_entity("test", "second");
        let params = put_params_with_expected(Some(&e2), Some(Hash::zero()));
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/taken".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        assert_eq!(cbor_map_get(map, "code").as_text(), Some("hash_mismatch"));
        // Binding unchanged.
        assert_eq!(tree.get("cas/taken").unwrap().content_hash, h1);
    }

    #[tokio::test]
    async fn test_handler_put_cas_create_remove_zero_hash_unbound_noop_ok() {
        // V7 §3.9 v7.50: remove with expected_hash = zero on an unbound path
        // → idempotent no-op (200, removed: false). "Applies to both write and
        // remove".
        let tree = make_tree();
        let params = put_params_with_expected(None, Some(Hash::zero()));
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/never".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert!(!tree.has("cas/never"));
    }

    #[tokio::test]
    async fn test_handler_put_cas_create_remove_zero_hash_bound_returns_409() {
        // V7 §3.9 v7.50: remove with expected_hash = zero on a bound path
        // → 409 (you expected absent but the path has a binding).
        let tree = make_tree();
        let e1 = make_entity("test", "v1");
        tree.put("cas/exists", e1).unwrap();

        let params = put_params_with_expected(None, Some(Hash::zero()));
        let ctx = make_handler_context("put", Some(params), Some(vec!["cas/exists".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_CONFLICT);
        // Binding still present.
        assert!(tree.has("cas/exists"));
    }

    // -----------------------------------------------------------------------
    // SNAPSHOT operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_snapshot_uses_tracked_root_when_present() {
        // Seed a tracked root binding directly (no wrapper entity) —
        // handle_snapshot must return it verbatim (EXTENSION-TREE §3.4.1).
        let tree = make_tree();
        let pid = test_peer_id();

        let fake_root = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("fake-root")));
        tree.location_index
            .set(&format!("/{}/system/tree/root/project", pid), fake_root);
        // Also seed real bindings — the fast path should still win.
        tree.put(&format!("/{}/project/a", pid), make_entity("t", "a"))
            .unwrap();

        let ctx = make_handler_context(
            "snapshot",
            None,
            Some(vec![format!("/{}/project/", pid)]),
        );
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let root_bytes = cbor_map_get(map, "root").as_bytes().unwrap();
        let got_root = Hash::from_bytes(root_bytes).unwrap();
        assert_eq!(
            got_root, fake_root,
            "snapshot fast path must return the tracked root"
        );
    }

    #[tokio::test]
    async fn test_handler_snapshot_empty_tree() {
        let tree = make_tree();
        let ctx = make_handler_context("snapshot", None, Some(vec!["docs/".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_TREE_SNAPSHOT);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let root_bytes = cbor_map_get(map, "root").as_bytes().unwrap();
        assert_eq!(root_bytes.len(), 33, "root should be a 33-byte hash");
        let root_hash = Hash::from_bytes(root_bytes).unwrap();
        let bindings = trie::collect_all_bindings(tree.content_store.as_ref(), root_hash, "");
        assert!(bindings.is_empty());
    }

    #[tokio::test]
    async fn test_handler_snapshot_populated() {
        let tree = make_tree();
        let e1 = make_entity("test", "alpha");
        let e2 = make_entity("test", "beta");
        tree.put("docs/a", e1.clone()).unwrap();
        tree.put("docs/b", e2.clone()).unwrap();
        tree.put("other/c", make_entity("test", "gamma")).unwrap();

        let ctx = make_handler_context("snapshot", None, Some(vec!["docs/".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let root_bytes = cbor_map_get(map, "root").as_bytes().unwrap();
        assert_eq!(root_bytes.len(), 33, "root should be a 33-byte hash");
        let root_hash = Hash::from_bytes(root_bytes).unwrap();
        let bindings = trie::collect_all_bindings(tree.content_store.as_ref(), root_hash, "");
        assert_eq!(bindings.len(), 2);

        // Verify relative paths
        let a_hash = bindings.get("a").expect("binding 'a' should exist");
        assert_eq!(*a_hash, e1.content_hash);
    }

    #[tokio::test]
    async fn test_handler_snapshot_invalid_prefix() {
        let tree = make_tree();
        let ctx = make_handler_context("snapshot", None, Some(vec!["docs".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    /// V7 §3.2 confused-deputy regression — PROPOSAL-CROSS-IMPL-STANDARDIZATION-
    /// CATCHUP §3. When tree:snapshot reads its prefix from params (not
    /// resource_target), the dispatch-layer auth check did not see that path,
    /// so the handler MUST perform its own check. Without the fix, a caller
    /// authorized for one prefix could snapshot a different one.
    #[tokio::test]
    async fn test_handler_snapshot_params_prefix_auth_checked() {
        use entity_capability::{
            check_permission, CapabilityToken, GrantEntry, Granter, IdScope, PathScope,
            ResourceTarget,
        };

        let tree = make_tree();
        let peer = test_peer_id();

        // Build a cap granting snapshot on `/peer/system/tree` ONLY for the
        // `docs/` prefix.
        let allowed_prefix = format!("/{}/docs/", peer);
        let attempted_prefix = format!("/{}/secret/", peer);
        let grant = GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec![allowed_prefix.clone()]),
            operations: IdScope::new(vec!["snapshot".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        };
        let cap = CapabilityToken {
            grants: vec![grant],
            granter: Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };

        // Sanity: dispatch-layer check would PASS for allowed, FAIL for
        // attempted (proves the cap shape is correct).
        let allowed_target = ResourceTarget {
            targets: vec![allowed_prefix.clone()],
            exclude: vec![],
        };
        let attempted_target = ResourceTarget {
            targets: vec![attempted_prefix.clone()],
            exclude: vec![],
        };
        let pattern = format!("/{}/system/tree", peer);
        assert!(check_permission(
            "snapshot",
            &pattern,
            &peer,
            Some(&allowed_target),
            &cap,
            &peer
        ));
        assert!(!check_permission(
            "snapshot",
            &pattern,
            &peer,
            Some(&attempted_target),
            &cap,
            &peer
        ));

        // Build a context: NO resource_target, params carries the attempted
        // prefix. Without the §3.2 handler-side check this would silently
        // return a snapshot of `/peer/secret/`.
        let params_val = entity_ecf::Value::Map(vec![(
            entity_ecf::text("prefix"),
            entity_ecf::text(&attempted_prefix),
        )]);
        let mut ctx = make_handler_context("snapshot", Some(params_val), None);
        ctx.caller_capability = Some(cap);

        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(
            result.status, STATUS_FORBIDDEN,
            "snapshot with params.prefix MUST be auth-checked when not in resource_target"
        );
    }

    #[tokio::test]
    async fn test_handler_snapshot_determinism() {
        let tree = make_tree();
        tree.put("data/x", make_entity("test", "x")).unwrap();
        tree.put("data/y", make_entity("test", "y")).unwrap();

        let ctx1 = make_handler_context("snapshot", None, Some(vec!["data/".into()]));
        let r1 = tree.handle(&ctx1).await.unwrap();

        let ctx2 = make_handler_context("snapshot", None, Some(vec!["data/".into()]));
        let r2 = tree.handle(&ctx2).await.unwrap();

        assert_eq!(r1.result.content_hash, r2.result.content_hash);
    }

    #[tokio::test]
    async fn test_handler_snapshot_full_tree() {
        let tree = make_tree();
        tree.put("a", make_entity("test", "a")).unwrap();
        tree.put("b", make_entity("test", "b")).unwrap();

        // Empty prefix = full tree
        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("prefix"),
            entity_ecf::text(""),
        )]);
        let ctx = make_handler_context("snapshot", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();
        let root_bytes = cbor_map_get(map, "root").as_bytes().unwrap();
        assert_eq!(root_bytes.len(), 33, "root should be a 33-byte hash");
        let root_hash = Hash::from_bytes(root_bytes).unwrap();
        let bindings = trie::collect_all_bindings(tree.content_store.as_ref(), root_hash, "");
        assert_eq!(bindings.len(), 2);
    }

    // -----------------------------------------------------------------------
    // DIFF operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_diff_added_removed_changed() {
        let tree = make_tree();

        // Create base snapshot: a, b, c
        tree.put("data/a", make_entity("test", "a1")).unwrap();
        tree.put("data/b", make_entity("test", "b1")).unwrap();
        tree.put("data/c", make_entity("test", "c1")).unwrap();

        let snap1_ctx = make_handler_context("snapshot", None, Some(vec!["data/".into()]));
        let snap1 = tree.handle(&snap1_ctx).await.unwrap();
        // Store snapshot in content store
        let snap1_hash = tree.content_store.put(snap1.result.clone()).unwrap();

        // Modify tree: remove b, change c, add d
        tree.remove("data/b");
        tree.put("data/c", make_entity("test", "c2")).unwrap();
        tree.put("data/d", make_entity("test", "d1")).unwrap();

        let snap2_ctx = make_handler_context("snapshot", None, Some(vec!["data/".into()]));
        let snap2 = tree.handle(&snap2_ctx).await.unwrap();
        let snap2_hash = tree.content_store.put(snap2.result.clone()).unwrap();

        // Diff
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(snap1_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(snap2_hash.to_bytes().to_vec()),
            ),
        ]);
        let diff_ctx = make_handler_context("diff", Some(params), None);
        let diff_result = tree.handle(&diff_ctx).await.unwrap();
        assert_eq!(diff_result.status, STATUS_OK);
        assert_eq!(diff_result.result.entity_type, entity_types::TYPE_TREE_DIFF);

        let val = decode_cbor(&diff_result.result.data);
        let map = val.as_map().unwrap();

        let added = cbor_map_get(map, "added").as_map().unwrap();
        assert_eq!(added.len(), 1); // d
        assert!(added.iter().any(|(k, _)| k.as_text() == Some("d")));

        let removed = cbor_map_get(map, "removed").as_map().unwrap();
        assert_eq!(removed.len(), 1); // b
        assert!(removed.iter().any(|(k, _)| k.as_text() == Some("b")));

        let changed = cbor_map_get(map, "changed").as_map().unwrap();
        assert_eq!(changed.len(), 1); // c
        assert!(changed.iter().any(|(k, _)| k.as_text() == Some("c")));

        let unchanged = cbor_map_get(map, "unchanged").as_integer().unwrap();
        assert_eq!(i128::from(unchanged), 1); // a
    }

    #[tokio::test]
    async fn test_handler_diff_snapshot_not_found() {
        let tree = make_tree();
        let fake_hash = Hash::compute("fake", &[1, 2, 3]);
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(fake_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(fake_hash.to_bytes().to_vec()),
            ),
        ]);
        let ctx = make_handler_context("diff", Some(params), None);
        let result = tree.handle(&ctx).await;
        let result = result.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // MERGE operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_merge_new_paths() {
        let tree = make_tree();

        // Create source snapshot with entries
        tree.put("src/a", make_entity("test", "a")).unwrap();
        tree.put("src/b", make_entity("test", "b")).unwrap();

        let snap_ctx = make_handler_context("snapshot", None, Some(vec!["src/".into()]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        // Merge into empty target (no prefix remap)
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("source_prefix"),
                entity_ecf::text("src/"),
            ),
            (
                entity_ecf::text("target_prefix"),
                entity_ecf::text("dest/"),
            ),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let applied = cbor_map_get(map, "applied").as_integer().unwrap();
        assert_eq!(i128::from(applied), 2);

        let skipped = cbor_map_get(map, "skipped").as_integer().unwrap();
        assert_eq!(i128::from(skipped), 0);

        // Verify paths were written
        assert!(tree.has("dest/a"));
        assert!(tree.has("dest/b"));
    }

    #[tokio::test]
    async fn test_handler_merge_no_overwrite_conflict() {
        let tree = make_tree();

        // Pre-existing entry
        tree.put("data/x", make_entity("test", "existing")).unwrap();

        // Source snapshot with conflicting entry
        tree.put("snap/x", make_entity("test", "incoming")).unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec!["snap/".into()]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("source_prefix"),
                entity_ecf::text("snap/"),
            ),
            (
                entity_ecf::text("target_prefix"),
                entity_ecf::text("data/"),
            ),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text("no-overwrite"),
            ),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let conflicts = cbor_map_get(map, "conflicts").as_map().unwrap();
        assert_eq!(conflicts.len(), 1);

        // Existing value should not be overwritten
        let existing = tree.get("data/x").unwrap();
        assert_eq!(existing, make_entity("test", "existing"));
    }

    #[tokio::test]
    async fn test_handler_merge_source_wins() {
        let tree = make_tree();
        let existing = make_entity("test", "existing");
        let incoming = make_entity("test", "incoming");
        tree.put("data/x", existing).unwrap();

        tree.put("snap/x", incoming.clone()).unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec!["snap/".into()]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("source_prefix"),
                entity_ecf::text("snap/"),
            ),
            (
                entity_ecf::text("target_prefix"),
                entity_ecf::text("data/"),
            ),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text("source-wins"),
            ),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let applied = cbor_map_get(map, "applied").as_integer().unwrap();
        assert_eq!(i128::from(applied), 1);

        // Source should win
        let stored = tree.get("data/x").unwrap();
        assert_eq!(stored.content_hash, incoming.content_hash);

        let conflicts = cbor_map_get(map, "conflicts").as_map().unwrap();
        assert_eq!(conflicts.len(), 1);
        let conflict = cbor_map_get(conflicts, "data/x").as_map().unwrap();
        let resolution = cbor_map_get(conflict, "resolution").as_text().unwrap();
        assert_eq!(resolution, "used-incoming");
    }

    #[tokio::test]
    async fn test_handler_merge_target_wins() {
        let tree = make_tree();
        let existing = make_entity("test", "existing");
        tree.put("data/x", existing.clone()).unwrap();

        tree.put("snap/x", make_entity("test", "incoming")).unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec!["snap/".into()]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("source_prefix"),
                entity_ecf::text("snap/"),
            ),
            (
                entity_ecf::text("target_prefix"),
                entity_ecf::text("data/"),
            ),
            (
                entity_ecf::text("strategy"),
                entity_ecf::text("target-wins"),
            ),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let skipped = cbor_map_get(map, "skipped").as_integer().unwrap();
        assert_eq!(i128::from(skipped), 1);

        // Existing should remain
        let stored = tree.get("data/x").unwrap();
        assert_eq!(stored.content_hash, existing.content_hash);
    }

    #[tokio::test]
    async fn test_handler_merge_dry_run() {
        let tree = make_tree();

        tree.put("src/a", make_entity("test", "a")).unwrap();
        let snap_ctx = make_handler_context("snapshot", None, Some(vec!["src/".into()]));
        let snap = tree.handle(&snap_ctx).await.unwrap();
        let snap_hash = tree.content_store.put(snap.result).unwrap();

        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("source"),
                entity_ecf::Value::Bytes(snap_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("source_prefix"),
                entity_ecf::text("src/"),
            ),
            (
                entity_ecf::text("target_prefix"),
                entity_ecf::text("dest/"),
            ),
            (
                entity_ecf::text("dry_run"),
                entity_ecf::bool_val(true),
            ),
        ]);

        let ctx = make_handler_context("merge", Some(params), None);
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        let applied = cbor_map_get(map, "applied").as_integer().unwrap();
        assert_eq!(i128::from(applied), 1);

        // But no actual write
        assert!(!tree.has("dest/a"));
    }

    // -----------------------------------------------------------------------
    // EXTRACT operation tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handler_extract_full_subtree() {
        let tree = make_tree();
        let e1 = make_entity("test", "alpha");
        let e2 = make_entity("test", "beta");
        tree.put("data/a", e1).unwrap();
        tree.put("data/b", e2).unwrap();

        let ctx = make_handler_context("extract", None, Some(vec!["data/".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, entity_types::TYPE_ENVELOPE);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        // Root should be a snapshot
        let root = cbor_map_get(map, "root").as_map().unwrap();
        let root_type = cbor_map_get(root, "type").as_text().unwrap();
        assert_eq!(root_type, entity_types::TYPE_TREE_SNAPSHOT);

        // Included should have the snapshot + trie nodes + 2 data entities
        // (snapshot + root trie node + 2 leaf trie nodes + 2 data entities = 6,
        // or fewer if trie compresses paths)
        let included = cbor_map_get(map, "included").as_map().unwrap();
        assert!(included.len() >= 3, "expected at least 3 included entities, got {}", included.len());
    }

    #[tokio::test]
    async fn test_handler_extract_with_paths_filter() {
        let tree = make_tree();
        tree.put("data/a", make_entity("test", "alpha")).unwrap();
        tree.put("data/b", make_entity("test", "beta")).unwrap();
        tree.put("data/c", make_entity("test", "gamma")).unwrap();

        let params = entity_ecf::Value::Map(vec![(
            entity_ecf::text("paths"),
            entity_ecf::array(vec![entity_ecf::text("a"), entity_ecf::text("c")]),
        )]);

        let ctx = make_handler_context("extract", Some(params), Some(vec!["data/".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val = decode_cbor(&result.result.data);
        let map = val.as_map().unwrap();

        // Root snapshot should have only 2 bindings (a, c)
        let root = cbor_map_get(map, "root").as_map().unwrap();
        let root_data_val = cbor_map_get(root, "data");
        let mut root_data_bytes = Vec::new();
        ciborium::into_writer(root_data_val, &mut root_data_bytes).unwrap();
        let root_data: ciborium::Value = ciborium::from_reader(root_data_bytes.as_slice()).unwrap();
        let root_map = root_data.as_map().unwrap();
        let trie_root_bytes = cbor_map_get(root_map, "root").as_bytes().unwrap();
        let trie_root_hash = Hash::from_bytes(trie_root_bytes).unwrap();
        let bindings = trie::collect_all_bindings(tree.content_store.as_ref(), trie_root_hash, "");
        assert_eq!(bindings.len(), 2);
    }

    #[tokio::test]
    async fn test_handler_extract_invalid_prefix() {
        let tree = make_tree();
        let ctx = make_handler_context("extract", None, Some(vec!["data".into()]));
        let result = tree.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // Round-trip: snapshot → diff → merge → extract
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_round_trip() {
        let tree = make_tree();

        // Set up initial data
        tree.put("app/config", make_entity("test", "config-v1")).unwrap();
        tree.put("app/data", make_entity("test", "data-v1")).unwrap();

        // Snapshot before
        let snap1_ctx = make_handler_context("snapshot", None, Some(vec!["app/".into()]));
        let snap1 = tree.handle(&snap1_ctx).await.unwrap();
        let snap1_hash = tree.content_store.put(snap1.result).unwrap();

        // Modify
        tree.put("app/data", make_entity("test", "data-v2")).unwrap();
        tree.put("app/new", make_entity("test", "new-entry")).unwrap();

        // Snapshot after
        let snap2_ctx = make_handler_context("snapshot", None, Some(vec!["app/".into()]));
        let snap2 = tree.handle(&snap2_ctx).await.unwrap();
        let snap2_hash = tree.content_store.put(snap2.result).unwrap();

        // Diff should show 1 changed (data), 1 added (new), 1 unchanged (config)
        let diff_params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("base"),
                entity_ecf::Value::Bytes(snap1_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(snap2_hash.to_bytes().to_vec()),
            ),
        ]);
        let diff_ctx = make_handler_context("diff", Some(diff_params), None);
        let diff = tree.handle(&diff_ctx).await.unwrap();
        assert_eq!(diff.status, STATUS_OK);

        let val = decode_cbor(&diff.result.data);
        let map = val.as_map().unwrap();
        let added = cbor_map_get(map, "added").as_map().unwrap();
        let changed = cbor_map_get(map, "changed").as_map().unwrap();
        let unchanged = cbor_map_get(map, "unchanged").as_integer().unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(changed.len(), 1);
        assert_eq!(i128::from(unchanged), 1);

        // Extract subtree
        let extract_ctx = make_handler_context("extract", None, Some(vec!["app/".into()]));
        let extract = tree.handle(&extract_ctx).await.unwrap();
        assert_eq!(extract.status, STATUS_OK);
        assert_eq!(extract.result.entity_type, entity_types::TYPE_ENVELOPE);
    }

}
