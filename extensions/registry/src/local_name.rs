//! Local-name backend (§6) — the v1 concrete registry backend.
//!
//! Handler `system/registry/local-name` serving `:bind` / `:unbind` / `:list` /
//! `:update-transports`. Two-layer storage: the immutable binding **body** at
//! `system/registry/binding/{hash}` (§3 universal) + a mutable **tree pointer**
//! at `system/registry/binding/local-name/{name}` (the live name→hash index, §6.3).
//! No `system/signature` — the user is the trust source (§6.3 carve-out).
//!
//! The meta-resolver (`resolver.rs`) calls [`resolve_one`] directly for
//! `local-name` chain entries; the local-name handler itself does not expose a wire
//! `:resolve` op (that's the substrate `system/registry:resolve` surface).

use std::sync::Arc;

use async_trait::async_trait;
use entity_ecf::{text, Value};
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_CONFLICT,
    STATUS_NOT_FOUND,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::data::{
    decode_map, get_field, normalize_name, validate_name_safety, BindingData, LocalNameConfigData,
    ResolutionResult, KIND_LOCAL_NAME, STATUS_RESOLVED, TRUST_LOCAL_NAME,
};
use crate::log::now_ms;
use crate::result::{error, hash_result, status_result};
use crate::{
    binding_body_path, local_name_config_path, local_name_pointer_path, local_name_pointer_prefix,
};

/// Load the peer's local-name-config, falling back to defaults when absent.
pub fn load_local_name_config(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    peer_id: &str,
) -> LocalNameConfigData {
    location_index
        .get(&local_name_config_path(peer_id))
        .and_then(|h| content_store.get(&h))
        .and_then(|e| LocalNameConfigData::from_entity(&e).ok())
        .unwrap_or_default()
}

/// Backend resolve (§6.5) — invoked by the meta-resolver for `local-name` chain
/// entries. Applies the same NFC + case normalization as `:bind` before lookup
/// (normalization symmetry, absorption §5.4). Empty transports still resolve.
pub fn resolve_one(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    peer_id: &str,
    config: &LocalNameConfigData,
    name: &str,
) -> Option<ResolutionResult> {
    let key = normalize_name(name, &config.case_normalization);
    let pointer = location_index.get(&local_name_pointer_path(peer_id, &key))?;
    let body = content_store.get(&pointer)?;
    let binding = BindingData::from_entity(&body).ok()?;
    Some(ResolutionResult {
        status: STATUS_RESOLVED.into(),
        binding: Some(pointer),
        peer_id: Some(binding.target_peer_id),
        transports: binding.transports,
        attestations: Vec::new(),
        trust_anchor: Some(TRUST_LOCAL_NAME.into()),
        ttl: None,
        neg_ttl: None,
        backend_id: Some(peer_id.to_string()),
    })
}

/// `system/registry/local-name` handler.
pub struct LocalNameHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    peer_id: String,
    qualified_pattern: String,
}

impl LocalNameHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/registry/local-name", local_peer_id);
        Self {
            content_store,
            location_index,
            peer_id: local_peer_id,
            qualified_pattern,
        }
    }

    fn config(&self) -> LocalNameConfigData {
        load_local_name_config(&self.content_store, &self.location_index, &self.peer_id)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for LocalNameHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "bind" => Ok(self.handle_bind(ctx)),
            "unbind" => Ok(self.handle_unbind(ctx)),
            "list" => Ok(self.handle_list(ctx)),
            "update-transports" => Ok(self.handle_update_transports(ctx)),
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown local-name op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "registry-local-name"
    }

    fn operations(&self) -> &[&str] {
        &["bind", "unbind", "list", "update-transports"]
    }
}

impl LocalNameHandler {
    // -------------------------------------------------------------------
    // §6.5 :bind
    // -------------------------------------------------------------------
    fn handle_bind(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let name = match get_field(&map, "name").and_then(|v| v.as_text()) {
            Some(n) => n.to_string(),
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "name required"),
        };
        let target = match get_field(&map, "target_peer_id").and_then(|v| v.as_text()) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => {
                return error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "target_peer_id required",
                )
            }
        };
        // §6.3 name-path safety (rejects `/`, control chars, non-NFC, empty).
        if let Err(reason) = validate_name_safety(&name) {
            return error(STATUS_BAD_REQUEST, "bind_invalid_name", &reason);
        }
        let config = self.config();
        let key = normalize_name(&name, &config.case_normalization);

        let transports = get_field(&map, "transports")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let notes = get_field(&map, "notes")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());

        let pointer_path = local_name_pointer_path(&self.peer_id, &key);
        let existing = self.location_index.get(&pointer_path);
        if existing.is_some() && !config.allow_supersede {
            return error(
                STATUS_CONFLICT,
                "bind_already_exists",
                "name already bound and allow_supersede is false",
            );
        }
        let supersedes = if config.allow_supersede { existing } else { None };

        self.write_binding(&key, target, transports, notes, supersedes, config.default_pinned)
    }

    // -------------------------------------------------------------------
    // §6.5 :unbind
    // -------------------------------------------------------------------
    fn handle_unbind(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let name = match get_field(&map, "name").and_then(|v| v.as_text()) {
            Some(n) => n.to_string(),
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "name required"),
        };
        let key = normalize_name(&name, &self.config().case_normalization);
        let pointer_path = local_name_pointer_path(&self.peer_id, &key);
        // Remove the tree pointer; the binding body remains in the content tree
        // (supersedes-chain preserved per the ATTESTATION audit discipline).
        match self.location_index.remove(&pointer_path) {
            Some(_) => status_result(vec![(text("unbound"), Value::Bool(true))]),
            None => error(STATUS_NOT_FOUND, "not_found", "no such local-name"),
        }
    }

    // -------------------------------------------------------------------
    // §6.5 :list — reads the tree-pointer prefix (the live index)
    // -------------------------------------------------------------------
    fn handle_list(&self, _ctx: &HandlerContext) -> HandlerResult {
        let prefix = local_name_pointer_prefix(&self.peer_id);
        let mut entries: Vec<Value> = Vec::new();
        for entry in self.location_index.list(&prefix) {
            let body = match self.content_store.get(&entry.hash) {
                Some(b) => b,
                None => continue,
            };
            let binding = match BindingData::from_entity(&body) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let (notes, pinned) = binding_metadata(&binding);
            let mut m: Vec<(Value, Value)> = vec![
                (text("name"), text(&binding.name)),
                (text("hash"), Value::Bytes(entry.hash.to_bytes().to_vec())),
                (text("target_peer_id"), text(&binding.target_peer_id)),
                (text("pinned"), Value::Bool(pinned)),
            ];
            if let Some(n) = notes {
                m.push((text("notes"), text(n)));
            }
            entries.push(Value::Map(m));
        }
        status_result(vec![(text("entries"), Value::Array(entries))])
    }

    // -------------------------------------------------------------------
    // §6.5 :update-transports — successor binding, same target
    // -------------------------------------------------------------------
    fn handle_update_transports(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let name = match get_field(&map, "name").and_then(|v| v.as_text()) {
            Some(n) => n.to_string(),
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "name required"),
        };
        let transports = get_field(&map, "transports")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let key = normalize_name(&name, &self.config().case_normalization);
        let pointer_path = local_name_pointer_path(&self.peer_id, &key);
        let existing = match self.location_index.get(&pointer_path) {
            Some(h) => h,
            None => return error(STATUS_NOT_FOUND, "not_found", "no such local-name"),
        };
        let prev = match self
            .content_store
            .get(&existing)
            .and_then(|e| BindingData::from_entity(&e).ok())
        {
            Some(p) => p,
            None => return error(STATUS_NOT_FOUND, "not_found", "head binding body missing"),
        };
        let (notes_ref, pinned) = binding_metadata(&prev);
        let notes = notes_ref.map(|s| s.to_string());
        let target = prev.target_peer_id;
        self.write_binding(&key, target, transports, notes, Some(existing), pinned)
    }

    // -------------------------------------------------------------------
    // Shared body+pointer write
    // -------------------------------------------------------------------
    fn write_binding(
        &self,
        key: &str,
        target_peer_id: String,
        transports: Vec<Value>,
        notes: Option<String>,
        supersedes: Option<Hash>,
        pinned: bool,
    ) -> HandlerResult {
        let mut meta: Vec<(Value, Value)> = vec![(text("pinned"), Value::Bool(pinned))];
        if let Some(n) = &notes {
            meta.push((text("notes"), text(n)));
        }
        let binding = BindingData {
            name: key.to_string(),
            kind: KIND_LOCAL_NAME.into(),
            target_peer_id,
            transports,
            issued_at: now_ms(),
            ttl: None,
            supersedes,
            issuer_attestation: None,
            metadata: Some(Value::Map(meta)),
        };
        let entity = match binding.to_entity() {
            Ok(e) => e,
            Err(e) => return error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()),
        };
        let hash = entity.content_hash;
        // Write body first, then pointer (§6.3 / strategy R2 atomicity note: a
        // failed pointer-write leaves an orphan body, GC'd later; correctness
        // preserved — :list/:resolve only follow the pointer).
        if let Err(e) = self.content_store.put(entity) {
            return error(STATUS_BAD_REQUEST, "store_failed", &e.to_string());
        }
        self.location_index
            .set(&binding_body_path(&self.peer_id, &hash), hash);
        self.location_index
            .set(&local_name_pointer_path(&self.peer_id, key), hash);
        hash_result("binding_hash", hash)
    }
}

/// Extract `(notes, pinned)` from a local-name binding's `metadata` map.
fn binding_metadata(binding: &BindingData) -> (Option<&str>, bool) {
    let map = match &binding.metadata {
        Some(Value::Map(m)) => m,
        _ => return (None, true),
    };
    let notes = map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("notes") {
            v.as_text()
        } else {
            None
        }
    });
    let pinned = map
        .iter()
        .find_map(|(k, v)| {
            if k.as_text() == Some("pinned") {
                match v {
                    Value::Bool(b) => Some(*b),
                    _ => None,
                }
            } else {
                None
            }
        })
        .unwrap_or(true);
    (notes, pinned)
}
