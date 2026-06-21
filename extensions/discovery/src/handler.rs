//! The `system/discovery` handler (§3, §8.1) — `:scan`, `:announce`,
//! `:announce-stop`.
//!
//! The handler is backend-agnostic: it owns the candidate-entity lifecycle and
//! the §3 surface, delegating the medium to pluggable [`DiscoveryBackend`]s. On
//! `:scan` it drives the backend's snapshot browse, writes each observation as
//! a `system/discovery/candidate/{backend}/{candidate_id}` entity into the tree
//! (§3.0), applies the §3.1 per-scan count ceiling (surfacing overflow, never
//! silent), and returns the [`ScanResult`] snapshot. `:announce` /
//! `:announce-stop` drive the backend's advertise lifecycle.
//!
//! Capability gating (§4 `discovery-scan` / `discovery-announce`) is enforced at
//! the dispatch layer against the envelope capability, exactly as for every
//! other handler — the handler body carries no cap checks (matches REGISTRY).
//!
//! Not yet wired here: the continuous watchable-session reap loop (§3.0.1) and
//! the §2.2 successor-candidate / decision admission path. The snapshot `:scan`
//! with its tree-write is the meaningful same-network MVP; the streaming half
//! layers on the same backend seam (`BackendEvent::Departed`).

use std::collections::HashMap;
use std::sync::Arc;

use entity_ecf::Value;
use entity_handler::{Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST};
use entity_store::{ContentStore, LocationIndex};

use crate::backend::{AnnounceParams, DiscoveryBackend, Observation};
use crate::data::{CandidateData, ScanResult};
use crate::result::{error, status_result};
use crate::{candidate_path, DEFAULT_SCAN_CEILING};

pub struct DiscoveryHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    peer_id: String,
    qualified_pattern: String,
    backends: HashMap<String, Arc<dyn DiscoveryBackend>>,
    scan_ceiling: usize,
}

impl DiscoveryHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        backends: Vec<Arc<dyn DiscoveryBackend>>,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/discovery", local_peer_id);
        let backends = backends
            .into_iter()
            .map(|b| (b.name().to_string(), b))
            .collect();
        Self {
            content_store,
            location_index,
            peer_id: local_peer_id,
            qualified_pattern,
            backends,
            scan_ceiling: DEFAULT_SCAN_CEILING,
        }
    }

    /// Override the §3.1 per-scan candidate-count ceiling (default
    /// [`DEFAULT_SCAN_CEILING`]).
    pub fn with_scan_ceiling(mut self, ceiling: usize) -> Self {
        self.scan_ceiling = ceiling;
        self
    }

    async fn handle_scan(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e),
        };
        let backend_name = match field_text(&map, "backend") {
            Some(b) => b,
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "backend required"),
        };
        let Some(backend) = self.backends.get(&backend_name) else {
            // §3.4: e.g. mDNS on wasm32, or any backend not built/registered.
            return error(
                STATUS_BAD_REQUEST,
                "unknown_backend",
                &format!("no discovery backend '{}' on this peer", backend_name),
            );
        };
        let filter = field_value(&map, "filter");

        let observations = match backend.scan(filter).await {
            Ok(o) => o,
            Err(e) => return error(entity_handler::STATUS_UNAVAILABLE, "backend_error", &e.to_string()),
        };

        // §3.1 ceiling: truncate to the bound, dropping the overflow from this
        // snapshot, and surface `truncated` + the overflow code — NEVER silent.
        let over = observations.len() > self.scan_ceiling;
        let kept = if over {
            &observations[..self.scan_ceiling]
        } else {
            &observations[..]
        };
        if over {
            tracing::warn!(
                backend = %backend_name,
                ceiling = self.scan_ceiling,
                observed = observations.len(),
                "discovery: scan over per-call ceiling; dropping overflow"
            );
        }

        // Write each kept observation as an immutable candidate entity (§2.1)
        // and a live tree pointer at the §3.0 watchable path.
        let now = now_ms();
        let mut hashes = Vec::with_capacity(kept.len());
        for obs in kept {
            match self.write_candidate(&backend_name, obs, now) {
                Ok(h) => hashes.push(h),
                Err(e) => {
                    return error(entity_handler::STATUS_INTERNAL_ERROR, "candidate_write_failed", &e)
                }
            }
        }

        let result = if over {
            ScanResult::overflow(hashes)
        } else {
            ScanResult::ok(hashes)
        };
        status_result(result.to_fields())
    }

    /// Build, store, and tree-link one candidate. `candidate_id` is the
    /// content-hash hex (§3.0). Idempotent: a re-scan of the same peer re-puts
    /// the identical content-addressed entity and re-sets the same pointer.
    fn write_candidate(
        &self,
        backend: &str,
        obs: &Observation,
        observed_at: i64,
    ) -> Result<entity_hash::Hash, String> {
        let candidate = CandidateData {
            peer_id: obs.peer_id.clone(),
            backend: backend.to_string(),
            observed_at,
            endpoint_hint: obs.endpoint_hint.clone(),
            // v1 mDNS makes no signed identity claim — TOFU (§2.2.1 null).
            identity_hint: None,
            // Snapshot candidates are fresh observations, not successors (§2.2).
            supersedes: None,
        };
        let entity = candidate.to_entity().map_err(|e| e.to_string())?;
        let hash = self
            .content_store
            .put(entity)
            .map_err(|e| e.to_string())?;
        let path = candidate_path(&self.peer_id, backend, &hash.to_hex());
        self.location_index.set(&path, hash);
        Ok(hash)
    }

    async fn handle_announce(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e),
        };
        let backend_name = match field_text(&map, "backend") {
            Some(b) => b,
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "backend required"),
        };
        let profile_ref = match field_text(&map, "profile_ref") {
            Some(p) => p,
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "profile_ref required"),
        };
        let Some(backend) = self.backends.get(&backend_name) else {
            return error(
                STATUS_BAD_REQUEST,
                "unknown_backend",
                &format!("no discovery backend '{}' on this peer", backend_name),
            );
        };

        // The announcing peer advertises ITS OWN peer-id as the §3.2
        // peer_id_hint. port/proto/display_name are caller-supplied hints
        // describing the transport the profile_ref names.
        let params = AnnounceParams {
            profile_ref: profile_ref.clone(),
            peer_id: Some(self.peer_id.clone()),
            proto: field_text(&map, "proto"),
            display_name: field_text(&map, "display_name"),
            port: field_u64(&map, "port").unwrap_or(0) as u16,
        };
        match backend.announce(&params).await {
            Ok(()) => status_result(vec![
                (entity_ecf::text("announced"), Value::Bool(true)),
                (entity_ecf::text("profile_ref"), entity_ecf::text(&profile_ref)),
            ]),
            Err(e) => error(entity_handler::STATUS_UNAVAILABLE, "backend_error", &e.to_string()),
        }
    }

    async fn handle_announce_stop(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e),
        };
        let backend_name = match field_text(&map, "backend") {
            Some(b) => b,
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "backend required"),
        };
        let profile_ref = match field_text(&map, "profile_ref") {
            Some(p) => p,
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "profile_ref required"),
        };
        let Some(backend) = self.backends.get(&backend_name) else {
            return error(
                STATUS_BAD_REQUEST,
                "unknown_backend",
                &format!("no discovery backend '{}' on this peer", backend_name),
            );
        };
        match backend.announce_stop(&profile_ref).await {
            Ok(()) => status_result(vec![(entity_ecf::text("stopped"), Value::Bool(true))]),
            Err(e) => error(entity_handler::STATUS_UNAVAILABLE, "backend_error", &e.to_string()),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Handler for DiscoveryHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "scan" => Ok(self.handle_scan(ctx).await),
            "announce" => Ok(self.handle_announce(ctx).await),
            "announce-stop" => Ok(self.handle_announce_stop(ctx).await),
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown discovery op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "discovery"
    }

    fn operations(&self) -> &[&str] {
        &["scan", "announce", "announce-stop"]
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn now_ms() -> i64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn decode_map(data: &[u8]) -> Result<Vec<(Value, Value)>, String> {
    let v: Value = ciborium::from_reader(data).map_err(|e| e.to_string())?;
    v.into_map().map_err(|_| "expected CBOR map params".to_string())
}

fn field_text(map: &[(Value, Value)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) {
            v.as_text().map(|s| s.to_string())
        } else {
            None
        }
    })
}

fn field_u64(map: &[(Value, Value)], key: &str) -> Option<u64> {
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) {
            v.as_integer().and_then(|i| u64::try_from(i).ok())
        } else {
            None
        }
    })
}

fn field_value(map: &[(Value, Value)], key: &str) -> Option<Value> {
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some(key) && !matches!(v, Value::Null) {
            Some(v.clone())
        } else {
            None
        }
    })
}
