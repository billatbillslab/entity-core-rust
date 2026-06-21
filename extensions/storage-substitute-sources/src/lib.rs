//! EXTENSION-STORAGE-SUBSTITUTE-SOURCES v1 — chain-consultation substrate.
//!
//! On a local `system/content:get` miss the CONTENT extension invokes the
//! substitute-consultation hook defined here (§5 of the proposal — the
//! CONTENT v3.6 → v3.7 miss-hook). The hook walks an ordered chain of
//! `system/substitute/source` entries; for each enabled entry it dispatches
//! to `system/substitute/<type>:try` and verifies the returned bytes
//! against the requested content hash.
//!
//! Per Sketch B (proposal §1): this crate is the type-agnostic substrate.
//! Per-source-type fetch mechanics are delegated to convention extensions
//! that register their own handler (e.g.
//! `entity-storage-substitute-http` provides `system/substitute/http`).
//!
//! Scope of this initial landing (v1.0 — content-half):
//! - Entity type `system/substitute/source` (§2.1)
//! - Endpoint entity type `system/substitute/endpoint` (Ruling 1)
//! - Try-request entity type `system/substitute/try-request` carrying
//!   the FULL source entity inline (Ruling 2)
//! - Required-signature trust contract (§2.4)
//! - Chain consultation algorithm (§2.2) — handler-URI dispatch via
//!   `ExecuteFn`, hash-verify on bytes, advance/abort error semantics
//! - Bare-hash-query short-circuit (§3-RES.2)
//! - Cap-path constants (§2.5)
//!
//! Manifest-/seq-/predecessor-freshness machinery lives in the convention
//! crate; this substrate is convention-agnostic. The manifest path
//! itself is **deferred to v1.1** all-three-impls-together per Ruling 5
//! (avoids the Python-only conformance edge).
//!
//! **Tree-half deferred to Phase 2.** Today this substrate hooks
//! `system/content:get` miss (hash-verified bytes). The storage-tree
//! half — fetching path→hash mutable signed-pointer bindings — belongs
//! in the Phase-2 transport-composition exploration (dispatcher
//! tree-fetch fallback + signed-pointer trust). v1.0 is correctly
//! described as the content backend of a storage substitute.

#![deny(missing_docs)]

use std::sync::Arc;

use async_trait::async_trait;
use entity_capability::{CapabilityToken, ResourceTarget};
use entity_content::miss_hook::{MissOutcome, MissResolver};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_handler::{ExecuteFn, ExecuteOptions};
use entity_store::{ContentStore, LocationIndex};

mod data;
mod verify;

pub use data::{decode_substitute_source, SubstituteSourceData};

// ===========================================================================
// Constants — entity types + cap paths
// ===========================================================================

/// Entity type for the substitute-source entry (§2.1).
pub const TYPE_SUBSTITUTE_SOURCE: &str = "system/substitute/source";

/// Entity type for a substitute endpoint payload (Ruling 1).
///
/// Each convention extension (`http`, future `peer-to-peer`, future
/// `nix-cache`, …) defines its OWN field shape inside an entity of this
/// type — the type name is the shared cohesion point; the field
/// vocabulary is convention-specific. For `http` see
/// `entity-storage-substitute-http`'s `EndpointConfig`.
///
/// Source-entry encoding: the source's `data.endpoint` field carries the
/// endpoint as raw bytes — `ciborium::Value::Bytes(encode_entity(endpoint))`
/// — preserving byte fidelity for hash verification per CLAUDE.md's
/// interop pitfall ("Entity data must preserve byte fidelity — never
/// decode+re-encode").
pub const TYPE_SUBSTITUTE_ENDPOINT: &str = "system/substitute/endpoint";

/// Entity type for the convention's try-request params (Ruling 2).
///
/// Replaces v0's `system/substitute/try-params`. Carries the FULL source
/// entity (encoded inline as bytes) plus the target content hash — the
/// convention handler doesn't need to re-look up the source from the
/// local store.
pub const TYPE_SUBSTITUTE_TRY_REQUEST: &str = "system/substitute/try-request";

/// Path prefix under which substitute-source entries are listed (§3-RES.4).
///
/// The full path is `system/substitute/sources/{substitute_hash}`. The
/// chain-consultation algorithm enumerates this prefix to find candidate
/// entries. Note: kept in the `system/substitute/*` namespace — clean
/// separation from `system/content/*` per §3-RES.4.
pub const PATH_PREFIX_SUBSTITUTE_SOURCES: &str = "system/substitute/sources/";

/// Capability path gating chain consultation (§2.5).
///
/// In-process cheap cap; checked before walking the chain. Lives in the
/// capability namespace rather than the content matrix so it composes
/// orthogonally with CONTENT §6.4 (per §3-RES.4 of the proposal).
///
/// **Mapping to the V7 4-axis grant model** (per the
/// named-capability-mapping ruling): this named cap reduces
/// to a `check_permission` call against
/// `(handler="system/substitute/sources", operation="consult",
/// resource=target_namespace)`. The substring `"content-substitute-consult"`
/// is impl shorthand only; the wire-checkable grant lives in the
/// handler-pattern + operation pair below ([`HANDLER_PATTERN_SOURCES`],
/// [`OP_CONSULT`]). The standalone string is retained for the doc-rot
/// pass + diagnostic logging; production checks MUST go through
/// `check_permission`, never through string presence.
pub const CAP_CONTENT_SUBSTITUTE_CONSULT: &str = "system/capability/content-substitute-consult";

/// Handler pattern for the cap-axis grant check
/// (named-capability-mapping ruling §4).
///
/// Combined with [`OP_CONSULT`] and an optional resource (`target_namespace`),
/// this is the `(handler, operation)` pair passed to V7 §5.2
/// `check_permission` to gate substrate consultation. The full
/// dispatch-form handler is `"/{local_peer_id}/system/substitute/sources"`;
/// the unqualified constant here is the cohort-pinned vocabulary.
pub const HANDLER_PATTERN_SOURCES: &str = "system/substitute/sources";

/// Operation id paired with [`HANDLER_PATTERN_SOURCES`] for the consult
/// cap-axis check.
pub const OP_CONSULT: &str = "consult";

/// Handler-URI template that the convention extensions register against.
/// Format: `system/substitute/<type>`. The substrate dispatches the
/// `try` operation against this URI for each chain entry; per §3-RES.3 of
/// the proposal this dissolves the "in-process registry" question — the
/// convention is just another handler at a known path.
pub const HANDLER_URI_PREFIX_SUBSTITUTE: &str = "system/substitute/";

/// Operation name dispatched against each convention extension (§3-RES.3).
pub const OP_TRY: &str = "try";

// ===========================================================================
// Hook trait — CONTENT calls this on local miss
// ===========================================================================

/// Reasons the substitute chain failed to produce a verified hit.
///
/// CONTENT translates these into wire-visible status codes (§3-RES.1):
/// - [`ConsultMiss::NoClaimedSource`], [`ConsultMiss::Disabled`],
///   [`ConsultMiss::Exhausted`] → 404 not_found with informative meta.
/// - [`ConsultMiss::Transient`] → 503 `substitute_chain_pending`.
/// - [`ConsultMiss::CapDenied`] → propagated upward as is (substrate
///   aborts the chain per §3-RES.10 / §5.1 — the consumer can't fetch via
///   this URL family at all and advancing to a same-family entry doesn't
///   help).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsultMiss {
    /// Substrate disabled or no chain entries are installed at all.
    Disabled,
    /// Query lacked a `claimed_source_peer_id` (bare-hash). Per §3-RES.2
    /// v1 does not consult the chain in this case.
    NoClaimedSource,
    /// Caller lacks `CAP_CONTENT_SUBSTITUTE_CONSULT`.
    CapDenied,
    /// Chain was consulted; every entry returned a transient error.
    /// Wire-visible as 503 `substitute_chain_pending`.
    Transient {
        /// Last entry's terminal error string (informative; for the
        /// §3-RES.7 meta on the 503).
        last_error: String,
        /// Number of chain entries attempted.
        attempted: usize,
    },
    /// Chain was consulted; every entry returned a terminal miss or
    /// failed verification. Wire-visible as 404 with
    /// `substitute_chain_attempted: true` per §3-RES.7.
    Exhausted {
        /// Last entry's terminal error string (informative; for the
        /// §3-RES.7 meta).
        last_error: Option<String>,
        /// Number of chain entries attempted.
        attempted: usize,
    },
}

/// Hook the CONTENT extension calls between its pending-sidecar check and
/// the terminal 404. Implementors walk a configured substitute-source
/// chain per §2.2 of the proposal.
///
/// CONTENT holds this as `Option<Arc<dyn SubstituteConsultHook>>`; when
/// the substrate extension is not installed the field is `None` and the
/// hook is never called (per §6 of the proposal: "Implementations without
/// the extension installed return 404 as today").
#[async_trait]
pub trait SubstituteConsultHook: Send + Sync {
    /// Walk the configured chain for a single missing hash.
    ///
    /// On a verified hit the bytes are returned to the caller. On any
    /// miss-reason the caller maps the result to a wire-visible status
    /// per [`ConsultMiss`]'s documentation.
    ///
    /// `claimed_source_peer_id` is the publisher identity carried with
    /// the query (e.g., from the entity's `refs.author`). When `None`,
    /// the v1 substrate short-circuits with [`ConsultMiss::NoClaimedSource`]
    /// per §3-RES.2 — wildcard / bare-hash consultation is out of v1
    /// scope.
    ///
    /// `caller_capability` + `resource_target` feed the cap-axis check
    /// pinned by the named-capability-mapping ruling: a V7 §5.2
    /// `check_permission` against `(handler=
    /// "/{local_peer_id}/system/substitute/sources", operation="consult",
    /// resource=target_namespace)`. **Fail closed:** any of (no token,
    /// wrong handler, wrong operation, resource outside scope) → returns
    /// [`ConsultMiss::CapDenied`] before enumerating chain entries.
    ///
    /// `execute_fn` is the parent's handler-to-handler dispatch closure
    /// (see [`ExecuteFn`]); the substrate uses it to invoke
    /// `system/substitute/<type>:try` for each chain entry.
    async fn consult(
        &self,
        hash: &Hash,
        claimed_source_peer_id: Option<&Hash>,
        caller_capability: Option<&CapabilityToken>,
        resource_target: Option<&ResourceTarget>,
        execute_fn: &ExecuteFn,
    ) -> Result<Entity, ConsultMiss>;
}

// ===========================================================================
// ChainConsultHook — the in-process implementation
// ===========================================================================

/// Default [`SubstituteConsultHook`] implementation backed by the local
/// content/location stores.
///
/// Holds shared references to the same stores CONTENT uses, so the
/// signature-verification path resolves source peer identity entities
/// out of the local tree. The hook is type-agnostic — convention
/// dispatch goes through `ExecuteFn` against the canonical
/// `system/substitute/<type>:try` URI.
pub struct ChainConsultHook {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
}

impl ChainConsultHook {
    /// Construct the hook with the stores the chain will be enumerated
    /// from. `local_peer_id` is the peer's own canonical Base58 peer-id
    /// string — used to qualify the location-index prefix the hook walks.
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: impl Into<String>,
    ) -> Self {
        Self {
            content_store,
            location_index,
            local_peer_id: local_peer_id.into(),
        }
    }

    /// Enumerate + filter + priority-sort the chain candidates for a
    /// single source peer. Exposed publicly for the §3-RES.7 informative
    /// meta path and for impl-side observability.
    pub fn candidates_for(&self, source_peer_id: &Hash) -> Vec<CandidateEntry> {
        let qualified_prefix = format!(
            "/{}/{}",
            self.local_peer_id, PATH_PREFIX_SUBSTITUTE_SOURCES
        );
        let now = now_epoch_ms();
        let mut candidates: Vec<CandidateEntry> = self
            .location_index
            .list(&qualified_prefix)
            .into_iter()
            .filter_map(|entry| {
                let body = self.content_store.get(&entry.hash)?;
                if body.entity_type != TYPE_SUBSTITUTE_SOURCE {
                    return None;
                }
                let data = decode_substitute_source(&body).ok()?;
                if !data.enabled {
                    return None;
                }
                if data.source_peer_id != *source_peer_id {
                    return None;
                }
                if let Some(expires_at) = data.expires_at {
                    if expires_at <= now {
                        return None;
                    }
                }
                if !self.verify_entry_signature(&entry.hash, &data) {
                    tracing::debug!(
                        path = %entry.path,
                        "substitute_consult: dropping entry — invalid or missing signature"
                    );
                    return None;
                }
                Some(CandidateEntry {
                    entry_hash: entry.hash,
                    entity: body,
                    data,
                })
            })
            .collect();
        candidates.sort_by_key(|c| c.data.priority);
        candidates
    }

    fn verify_entry_signature(&self, entry_hash: &Hash, data: &SubstituteSourceData) -> bool {
        verify::verify_entry_signature_against(
            entry_hash,
            &data.source_peer_id,
            self.content_store.as_ref(),
            self.location_index.as_ref(),
        )
    }
}

// ===========================================================================
// CONTENT v3.7 miss-hook adapter (per PROPOSAL §6)
// ===========================================================================

/// Bridge `ChainConsultHook` onto the CONTENT-side
/// [`MissResolver`] trait. Lets a `system/content` handler hold this
/// substrate's chain-consult logic as a generic `Arc<dyn MissResolver>`
/// without growing CONTENT's own dependencies.
///
/// Translation from the substrate-native [`ConsultMiss`] taxonomy to
/// CONTENT's batch-friendly [`MissOutcome`]:
///
/// - [`ConsultMiss::Disabled`] / [`ConsultMiss::NoClaimedSource`] /
///   [`ConsultMiss::CapDenied`] / [`ConsultMiss::Exhausted`] /
///   [`ConsultMiss::Transient`] → [`MissOutcome::NotResolved`] (the
///   batch caller pushes the hash to `missing` and retries the tail
///   per existing CONTENT semantics; the §3-RES.1 single-hash
///   503-vs-404 distinction is deferred to v1.1).
#[async_trait]
impl MissResolver for ChainConsultHook {
    async fn resolve_miss(
        &self,
        hash: &Hash,
        claimed_source_peer_id: Option<&Hash>,
        caller_capability: Option<&CapabilityToken>,
        resource_target: Option<&ResourceTarget>,
        execute_fn: &ExecuteFn,
    ) -> MissOutcome {
        match self
            .consult(
                hash,
                claimed_source_peer_id,
                caller_capability,
                resource_target,
                execute_fn,
            )
            .await
        {
            Ok(entity) => MissOutcome::Resolved(entity),
            Err(reason) => {
                tracing::debug!(
                    hash = %hash,
                    reason = ?reason,
                    "substitute_consult: chain returned non-hit"
                );
                MissOutcome::NotResolved
            }
        }
    }
}

/// Decoded chain candidate after signature verification + priority sort.
///
/// Carries both the entry's content hash (for handler dispatch) and the
/// raw entity body (so the convention handler can re-decode its own
/// type-specific fields without round-tripping through the store).
#[derive(Debug, Clone)]
pub struct CandidateEntry {
    /// Content hash of the substitute-source entry.
    pub entry_hash: Hash,
    /// Raw substitute-source entity (handed to the convention handler).
    pub entity: Entity,
    /// Decoded substitute-source data.
    pub data: SubstituteSourceData,
}

#[async_trait]
impl SubstituteConsultHook for ChainConsultHook {
    async fn consult(
        &self,
        hash: &Hash,
        claimed_source_peer_id: Option<&Hash>,
        caller_capability: Option<&CapabilityToken>,
        resource_target: Option<&ResourceTarget>,
        execute_fn: &ExecuteFn,
    ) -> Result<Entity, ConsultMiss> {
        // Cap-axis check per the named-capability-mapping ruling §4:
        // the consult cap reduces to a V7 §5.2 `check_permission` against
        // `(handler=/{local}/system/substitute/sources, op=consult,
        // resource=resource_target)`. **Fail closed** — absent token /
        // wrong handler / wrong op / wrong resource each deny BEFORE
        // enumerating chain entries (which would leak both presence and
        // ordering of the local chain to an unauthorized caller).
        let cap_ok = match caller_capability {
            Some(cap) => entity_capability::check_permission(
                OP_CONSULT,
                &format!("/{}/{}", self.local_peer_id, HANDLER_PATTERN_SOURCES),
                &self.local_peer_id,
                resource_target,
                cap,
                &self.local_peer_id,
            ),
            None => false,
        };
        if !cap_ok {
            return Err(ConsultMiss::CapDenied);
        }
        let source = match claimed_source_peer_id {
            Some(s) => s,
            None => return Err(ConsultMiss::NoClaimedSource),
        };

        let candidates = self.candidates_for(source);
        if candidates.is_empty() {
            return Err(ConsultMiss::Disabled);
        }

        let mut last_error: Option<String> = None;
        let mut any_transient = false;
        let attempted = candidates.len();

        for candidate in candidates {
            let handler_uri = format!(
                "{}{}",
                HANDLER_URI_PREFIX_SUBSTITUTE, candidate.data.substitute_type
            );
            tracing::debug!(
                hash = %hash,
                handler = %handler_uri,
                priority = candidate.data.priority,
                "substitute_consult: trying entry"
            );

            // Params shape (Ruling 2 — `system/substitute/try-request`):
            //   { entry: <bstr of encode_entity(source)>, hash: <bstr of requested_hash> }
            // The `entry` field carries the FULL source entity inline as
            // wire-encoded bytes. The convention handler decodes the
            // bytes back into an Entity directly — no local-store
            // re-lookup. Byte fidelity is preserved (the entity arrives
            // as raw bytes, never decoded-and-re-encoded in transit per
            // CLAUDE.md's interop pitfall).
            let entry_bytes = entity_wire::encode_entity(&candidate.entity);
            let params_value = build_try_request(&entry_bytes, hash);
            let params_bytes = match encode_value(&params_value) {
                Ok(b) => b,
                Err(e) => {
                    last_error = Some(format!("encode_failed: {}", e));
                    continue;
                }
            };
            let params = match Entity::new(TYPE_SUBSTITUTE_TRY_REQUEST, params_bytes) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(format!("encode_failed: {}", e));
                    continue;
                }
            };

            let result = (execute_fn)(
                handler_uri.clone(),
                OP_TRY.to_string(),
                params,
                ExecuteOptions::default(),
            )
            .await;

            match result {
                Ok(res) if res.status == entity_handler::STATUS_OK => {
                    // Convention handler returns the fetched entity as its
                    // `result`. The substrate hash-verifies via
                    // `Hash::compute(entity.entity_type, entity.data)` — the
                    // single source-of-trust for Mechanism A per the CDN
                    // proposal §1. Ingest of the verified entity is the
                    // caller's responsibility (§2.5's two-step cap shape:
                    // consult-cap gates the walk; ingest-cap gates the
                    // landing).
                    if verify::entity_hash_matches(hash, &res.result) {
                        return Ok(res.result);
                    }
                    tracing::warn!(
                        hash = %hash,
                        handler = %handler_uri,
                        "substitute_consult: hash mismatch — discarding + advancing"
                    );
                    last_error = Some("hash_mismatch".to_string());
                    continue;
                }
                Ok(res) if res.status == entity_handler::STATUS_NOT_FOUND => {
                    last_error = Some("not_found".to_string());
                    continue;
                }
                Ok(res) if res.status == entity_handler::STATUS_FORBIDDEN => {
                    // §3-RES.10 / §5.1: cap_denied on the type handler's
                    // own fetch ABORTS the chain (the consumer can't reach
                    // this URL family at all; advancing to the next entry
                    // doesn't help if all need the same denied cap).
                    return Err(ConsultMiss::CapDenied);
                }
                Ok(res) if is_transient(res.status) => {
                    any_transient = true;
                    last_error = Some(format!("transient_{}", res.status));
                    continue;
                }
                Ok(res) => {
                    last_error = Some(format!("status_{}", res.status));
                    continue;
                }
                Err(e) => {
                    any_transient = true;
                    last_error = Some(format!("handler_error: {}", e));
                    continue;
                }
            }
        }

        // Chain exhausted. 503 if at least one entry was transient (the
        // consumer's retry MAY help); 404 otherwise (no surviving entry
        // could plausibly serve the bytes).
        if any_transient {
            Err(ConsultMiss::Transient {
                last_error: last_error.unwrap_or_else(|| "unknown".to_string()),
                attempted,
            })
        } else {
            Err(ConsultMiss::Exhausted {
                last_error,
                attempted,
            })
        }
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

fn now_epoch_ms() -> u64 {
    use web_time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn is_transient(status: u32) -> bool {
    // 5xx and 429 are transient per the proposal's error-mapping table
    // §5.1 (CDN convention) — the substrate mirrors the discipline.
    status == entity_handler::STATUS_UNAVAILABLE
        || status == entity_handler::STATUS_BAD_GATEWAY
        || status == entity_handler::STATUS_RATE_LIMITED
        || status == entity_handler::STATUS_INTERNAL_ERROR
}

fn build_try_request(entry_entity_bytes: &[u8], target_hash: &Hash) -> ciborium::Value {
    use ciborium::Value;
    Value::Map(vec![
        (
            Value::Text("entry".to_string()),
            Value::Bytes(entry_entity_bytes.to_vec()),
        ),
        (
            Value::Text("hash".to_string()),
            Value::Bytes(target_hash.to_bytes().to_vec()),
        ),
    ])
}

fn encode_value(v: &ciborium::Value) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out)?;
    Ok(out)
}

