//! `system/substitute/http` handler — the convention's `try` op.
//!
//! Invoked by the substitute-sources substrate's chain-consult algorithm
//! when a chain entry's `substitute_type` is `"http"`. Mechanism A per
//! the STORAGE-SUBSTITUTE-HTTP proposal §1 — inline HTTP GET + hash
//! verification, NOT BRIDGE-HTTP.
//!
//! **Request shape (Ruling 2).** Params arrive as
//! `system/substitute/try-request` with `{entry, hash}`. The `entry`
//! field carries the FULL source entity inline as wire-encoded bytes;
//! the handler decodes those bytes into an `Entity` directly — no
//! local-store re-lookup of the source is needed.
//!
//! **Endpoint shape (Ruling 1).** The source's
//! `data.endpoint` field carries a `system/substitute/endpoint` entity,
//! also encoded inline as wire-format bytes. The HTTP convention's
//! [`EndpointConfig`] is the decoder for that entity's data (carrying
//! `tree_url_prefix`, `content_url_prefix`, `content_layout`,
//! `tree_leaf_suffix`).

use async_trait::async_trait;
use ciborium::Value;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_handler::{
    error_entity, Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_GATEWAY,
    STATUS_BAD_REQUEST, STATUS_NOT_FOUND, STATUS_UNAVAILABLE,
};

use entity_storage_substitute_sources::{decode_substitute_source, TYPE_SUBSTITUTE_SOURCE};

use crate::url::{build_content_url, EndpointConfig, UrlBuildError};
use crate::{PATTERN_HTTP, SUBSTITUTE_TYPE_HTTP};

/// The `system/substitute/http` handler.
///
/// Stateless except for a reused `reqwest::Client` (connection pooling +
/// TLS context survive across the chain-consult retries). No
/// `ContentStore` dependency post-Ruling-2: the source entity is
/// supplied inline in the try-request.
pub struct HttpSubstituteHandler {
    qualified_pattern: String,
    http: reqwest::Client,
}

impl HttpSubstituteHandler {
    /// Build the handler bound to `local_peer_id`. Uses reqwest's
    /// default client (rustls TLS; system trust roots; redirect-following).
    pub fn new(local_peer_id: &str) -> Self {
        Self::with_client(local_peer_id, reqwest::Client::new())
    }

    /// Inject a custom `reqwest::Client`. Useful for tests (mock TLS)
    /// and for deployments wiring per-environment timeouts / proxy
    /// settings.
    pub fn with_client(local_peer_id: &str, http: reqwest::Client) -> Self {
        Self {
            qualified_pattern: format!("/{}/{}", local_peer_id, PATTERN_HTTP),
            http,
        }
    }

    async fn handle_try(&self, ctx: &HandlerContext) -> HandlerResult {
        let params: Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => return bad_request("invalid_params", &format!("cbor: {}", e)),
        };
        let map = match &params {
            Value::Map(m) => m,
            _ => return bad_request("invalid_params", "expected CBOR map"),
        };

        let entry_bytes = match field_bytes(map, "entry") {
            Some(b) => b,
            None => {
                return bad_request(
                    "invalid_params",
                    "entry (wire-encoded source entity bytes) required",
                );
            }
        };
        let target_hash = match field_hash(map, "hash") {
            Some(h) => h,
            None => return bad_request("invalid_params", "hash required"),
        };

        // Decode the source entity from the inline bytes (Ruling 2).
        let source_entity = match entity_wire::decode_entity(&entry_bytes) {
            Ok(e) => e,
            Err(e) => {
                return bad_request(
                    "entry_decode",
                    &format!("failed to decode entry bytes as entity: {}", e),
                );
            }
        };
        if source_entity.entity_type != TYPE_SUBSTITUTE_SOURCE {
            return bad_request(
                "wrong_entry_type",
                &format!("entry has unexpected type: {}", source_entity.entity_type),
            );
        }
        let source_data = match decode_substitute_source(&source_entity) {
            Ok(d) => d,
            Err(e) => return bad_request("entry_decode", &e.to_string()),
        };
        if source_data.substitute_type != SUBSTITUTE_TYPE_HTTP {
            return bad_request(
                "wrong_substitute_type",
                &format!(
                    "entry.substitute_type = {}, expected {}",
                    source_data.substitute_type, SUBSTITUTE_TYPE_HTTP
                ),
            );
        }

        let endpoint = match EndpointConfig::decode_endpoint_field(source_data.endpoint.as_ref()) {
            Ok(e) => e,
            Err(e) => return bad_request("endpoint_decode", &e.to_string()),
        };

        let url = match build_content_url(&endpoint, &target_hash) {
            Ok(u) => u,
            Err(UrlBuildError::NonHttpsScheme(prefix)) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "non_https_scheme",
                        &format!("content URL prefix must be https://: {}", prefix),
                    ),
                );
            }
        };

        // Inline HTTP GET (Mechanism A). On any transport error we
        // return a transient status (5xx) so the substrate's chain-
        // consult advances to the next entry rather than aborting.
        let response = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(url = %url, error = %e, "http:try: network error");
                return HandlerResult::error(
                    STATUS_UNAVAILABLE,
                    error_entity("network_error", &e.to_string()),
                );
            }
        };
        let status = response.status();
        if !status.is_success() {
            // Map HTTP status: 404 → terminal; 5xx / 429 → transient;
            // other → bad-gateway transient (conservative).
            let mapped = if status == reqwest::StatusCode::NOT_FOUND {
                STATUS_NOT_FOUND
            } else if status.is_server_error() || status.as_u16() == 429 {
                STATUS_UNAVAILABLE
            } else {
                STATUS_BAD_GATEWAY
            };
            return HandlerResult::error(
                mapped,
                error_entity(
                    "http_status",
                    &format!("origin returned HTTP {}", status.as_u16()),
                ),
            );
        }

        let body = match response.bytes().await {
            Ok(b) => b.to_vec(),
            Err(e) => {
                return HandlerResult::error(
                    STATUS_UNAVAILABLE,
                    error_entity("read_body", &e.to_string()),
                );
            }
        };

        // Decode the fetched bytes' `(type, data)` form-agnostically — the
        // origin is an UNTRUSTED HTTP host, so we never read a wire-supplied
        // `content_hash`. (Publishers write the 3-key `encode_entity` form to
        // disk, but a hostile origin may serve anything; `decode_entity_parts`
        // tolerates both the 3-key and 2-key forms and ignores any wire hash.)
        let (entity_type, data) = match entity_wire::decode_entity_parts(&body) {
            Ok(parts) => parts,
            Err(e) => {
                tracing::warn!(
                    url = %url,
                    error = %e,
                    "http:try: failed to decode fetched bytes as entity"
                );
                return HandlerResult::error(
                    STATUS_BAD_GATEWAY,
                    error_entity("decode_entity", &e.to_string()),
                );
            }
        };

        // §1.2 host-bytes-distrust: RECOMPUTE the hash from the fetched
        // (type, data) under the requested hash's own format and require it to
        // reproduce `target_hash`. This is the trust gate — a host serving
        // bytes that do not re-hash to the requested hash (including one that
        // lies in a wire `content_hash` field) is rejected.
        let entity = match Entity::new_with_format(&entity_type, data, target_hash.algorithm) {
            Ok(e) if e.content_hash == target_hash => e,
            Ok(e) => {
                tracing::warn!(
                    url = %url,
                    recomputed = ?e.content_hash,
                    expected = ?target_hash,
                    "http:try: fetched bytes do not re-hash to the requested hash"
                );
                return HandlerResult::error(
                    STATUS_BAD_GATEWAY,
                    error_entity(
                        "hash_mismatch",
                        "fetched bytes do not re-hash to the requested content hash",
                    ),
                );
            }
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_GATEWAY,
                    error_entity("rehash", &e.to_string()),
                );
            }
        };

        HandlerResult::ok(entity)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for HttpSubstituteHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "try" => Ok(self.handle_try(ctx).await),
            other => Ok(bad_request(
                "unknown_operation",
                &format!("{} does not support {}", PATTERN_HTTP, other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "storage-substitute-http"
    }

    fn operations(&self) -> &[&str] {
        &["try"]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bad_request(code: &str, msg: &str) -> HandlerResult {
    HandlerResult::error(STATUS_BAD_REQUEST, error_entity(code, msg))
}

fn field_hash(map: &[(Value, Value)], key: &str) -> Option<Hash> {
    let bytes = field_bytes(map, key)?;
    Hash::from_bytes(bytes.as_slice()).ok()
}

fn field_bytes(map: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(t), Value::Bytes(b)) if t == key => Some(b.clone()),
        _ => None,
    })
}
