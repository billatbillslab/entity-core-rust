//! `system/content` handler — `get` (§6.2) + `ingest` (§6.3).
//!
//! Both ops require a `resource` field on the inbound EXECUTE per v3.5's
//! normative tightening (behavior change from v3.4). Without one, the
//! handler returns `STATUS_BAD_REQUEST` (400) with error type
//! `path_required` — matching the surface shape every other v7+ handler
//! uses for the same condition (attestation/identity/quorum precedent).
//!
//! - `get` walks `params.hashes`, looks each up in the content store,
//!   includes the resolved entities in the response envelope's
//!   `included` map, and returns `{found, missing}`.
//! - `ingest` accepts exactly one of `{envelope, entity}` in `params`.
//!   Envelope mode stores `envelope.root` + every `(hash, entity)` from
//!   `included`, validating each `content_hash(entity) == hash`. Result
//!   carries the original `envelope.root` inlined (§11.1 MUST) plus
//!   `root_hash` and `ingested_count`. Entity mode stores the single
//!   `entity` and returns its hash.
//!
//! The handler is type-agnostic — `get` returns any entity in the store
//! (blob, chunk, capability token, type def, …); §6 explicitly states
//! it's not a blob-only handler.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST,
};
use entity_store::{ContentStore, LocationIndex};

use crate::miss_hook::{MissOutcome, MissResolver};

/// Default frame budget for `get` responses, in bytes. Equals the
/// wire default (`DEFAULT_MAX_FRAME_SIZE` = 16 MiB) minus a fixed
/// headroom for the surrounding EXECUTE_RESPONSE envelope framing.
/// Override via [`SystemContentHandler::with_frame_budget`] when the
/// transport's configured budget differs (validate-peer
/// `frame-limit-respected` check; deployments tuning frame size).
///
/// Note on "configured budget at response-construction time" (CONTENT
/// v3.6 §6.2 / §4.2 Amendment 1): this handler holds one configured
/// budget per peer rather than reading per-connection state, which is
/// the simplest faithful reading of "configured, not hardcoded". When
/// per-connection budget plumbing lands, this field becomes the
/// fallback default.
pub const DEFAULT_GET_FRAME_BUDGET: u64 = (16 * 1024 * 1024) - (64 * 1024);

/// The optional `system/content` handler (§6).
pub struct SystemContentHandler {
    qualified_pattern: String,
    content_store: Arc<dyn ContentStore>,
    /// LocationIndex for writing the §6.4.2 Hash Tree Presence
    /// binding at ingest time. Optional **only** so call sites that
    /// pre-date the binding (tests, embedded uses) don't break — in
    /// production every peer instantiates with `Some(index)` so
    /// ingest writes the spec MUST.
    ///
    /// **CONTENT §6.4.2 MUST** (cohort-wide gap closed by arch
    /// ruling 1b5c125 §2.3): on every successful ingest
    /// into a namespace, write
    /// `LocationIndex[<namespace_uri>/{hex(H)}] = H` so that
    /// downstream `system/tree:get` and the http-poll NamespaceScope
    /// predicate find the content. Three impls (Go/Rust/Python)
    /// shipped without this; serving-mode E.4 surfaced the gap.
    location_index: Option<Arc<dyn LocationIndex>>,
    /// Configured frame budget for `get` responses. Receiver-side MUST
    /// per CONTENT v3.6 §6.2 / §4.2 Amendment 1 — included entities
    /// accumulated until the next addition would overflow the budget;
    /// remaining requested hashes move to `missing` per the spec contract
    /// even if locally present. Requester retries with the missing tail.
    get_frame_budget: u64,
    /// Optional substitute-source miss hook (CONTENT v3.7 amendment 4 —
    /// `PROPOSAL-CONTENT-SUBSTITUTE-SOURCES.md` §6). When `Some`, every
    /// local-store miss is offered to the hook before contributing to
    /// the response's `missing` list. When `None`, behavior is identical
    /// to v3.6 (terminal miss).
    miss_resolver: Option<Arc<dyn MissResolver>>,
}

impl SystemContentHandler {
    /// Construct the handler. Binds at `/{peer_id}/system/content`; the
    /// dispatcher's longest-prefix walk-back (V7 §6.6) routes every
    /// `system/content/{namespace}` URI here so namespace scoping
    /// (§6.4) can be enforced at the handler.
    ///
    /// Without [`Self::with_location_index`], ingest does NOT write
    /// the §6.4.2 binding — old call sites preserve their behavior.
    /// Production peers SHOULD pass a `LocationIndex`; the spec MUST
    /// fires only when one is wired.
    pub fn new(local_peer_id: &str, content_store: Arc<dyn ContentStore>) -> Self {
        Self {
            qualified_pattern: format!("/{}/system/content", local_peer_id),
            content_store,
            location_index: None,
            get_frame_budget: DEFAULT_GET_FRAME_BUDGET,
            miss_resolver: None,
        }
    }

    /// Wire the `LocationIndex` used to write the CONTENT §6.4.2 Hash
    /// Tree Presence binding on every successful ingest. Arch ruling
    /// 1b5c125 §2.3 — the spec MUST nobody implemented.
    pub fn with_location_index(mut self, index: Arc<dyn LocationIndex>) -> Self {
        self.location_index = Some(index);
        self
    }

    /// Override the configured `get`-response frame budget. Used by the
    /// `frame-limit-respected` validate-peer check (CONTENT v3.6 §6.2
    /// Amendment 1) and by deployments tuning the transport. Per-request
    /// per-connection plumbing is a future refinement; for now the value
    /// is a per-peer configuration knob.
    pub fn with_frame_budget(mut self, budget: u64) -> Self {
        self.get_frame_budget = budget;
        self
    }

    /// Install a substitute-source [`MissResolver`] (CONTENT v3.7
    /// amendment 4). When set, `handle_get` offers every local-store
    /// miss to the resolver before contributing the hash to the
    /// response's `missing` list. Default (`None`) preserves v3.6
    /// behavior.
    pub fn with_miss_resolver(mut self, resolver: Arc<dyn MissResolver>) -> Self {
        self.miss_resolver = Some(resolver);
        self
    }

    async fn handle_get(&self, ctx: &HandlerContext) -> HandlerResult {
        if !has_resource(ctx) {
            return path_required(
                "system/content:get requires a resource field naming the namespace path",
            );
        }
        let params: Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => return bad_request("invalid_params", &format!("cbor: {}", e)),
        };
        let hashes_v = match params.get("hashes").and_then(|v| v.as_array().cloned()) {
            Some(a) => a,
            None => return bad_request("invalid_params", "hashes required"),
        };

        // **Ruling 4** (storage-substitute cross-impl rulings):
        // `source_peer_id` (the claimed source for the substitute-consult
        // chain) is LOCAL dispatcher context, NOT a wire field on
        // `system/content:get-request`. The consumer's own dispatch path
        // already knows whose content it's fetching (it's walking that
        // peer's tree). Keeping the field off the wire honors the
        // Sketch-B discipline (don't grow core CONTENT's get-request
        // contract for an extension's needs).
        //
        // v1.0 holds the slot open via the resolver trait's
        // `claimed_source_peer_id: Option<&Hash>` argument and passes
        // `None` from this site — so CONTENT-level get-requests do NOT
        // trigger substitute consult by themselves. Real chain firing
        // happens via direct calls to `ChainConsultHook::consult` from
        // callers who DO have local source context (SDK closure-fetch
        // walking a known publisher's tree; future Phase-2 dispatcher
        // tree-fetch). Plumbing a local context channel here lands when
        // that driver materializes.
        let claimed_source: Option<Hash> = None;

        let mut found: Vec<Hash> = Vec::new();
        let mut missing: Vec<Hash> = Vec::new();
        let mut included: HashMap<Hash, Entity> = HashMap::new();

        // CONTENT v3.6 §6.2 / §4.2 Amendment 1 — frame-budget MUST.
        // Accumulate the wire cost of each included entity against the
        // configured budget; once adding the next entity would overflow,
        // route all remaining requested hashes to `missing` regardless
        // of local presence. The requester retries with the missing tail
        // per the spec contract.
        let budget = self.get_frame_budget;
        let mut used: u64 = 0;
        let mut budget_exhausted = false;

        for entry in &hashes_v {
            let h = match decode_hash_record(entry) {
                Ok(h) => h,
                Err(e) => return bad_request("invalid_params", &e),
            };
            if budget_exhausted {
                missing.push(h);
                continue;
            }

            let resolved_entity = match self.content_store.get(&h) {
                Some(entity) => Some(entity),
                None => {
                    // CONTENT v3.7 miss-hook (per
                    // `PROPOSAL-CONTENT-SUBSTITUTE-SOURCES.md` §6).
                    // Offer the miss to the optional resolver; when
                    // installed it walks the substitute-source chain.
                    self.try_substitute_resolve(&h, claimed_source.as_ref(), ctx)
                        .await
                }
            };

            match resolved_entity {
                Some(entity) => {
                    let cost = included_entry_cost(&entity);
                    let next = used.saturating_add(cost);
                    // Always include at least one entity if any fits at
                    // all — keeps progress under the SHOULD ("as many as
                    // fit, in request order") for first-item-larger-than-
                    // budget pathological cases.
                    if next > budget && !included.is_empty() {
                        budget_exhausted = true;
                        missing.push(h);
                    } else {
                        used = next;
                        included.insert(h, entity);
                        found.push(h);
                    }
                }
                None => missing.push(h),
            }
        }

        let result_data = encode_content_response(&found, &missing);
        let result = match Entity::new("system/content/content-response", result_data) {
            Ok(e) => e,
            Err(e) => return bad_request("encode_failed", &e.to_string()),
        };
        HandlerResult::ok_with_included(result, included)
    }

    /// Offer a local-store miss to the substitute-source hook.
    ///
    /// Returns `Some(entity)` when the chain resolved a verified entity;
    /// `None` when no resolver is installed, when the necessary
    /// preconditions for consulting the chain aren't met (missing
    /// `execute_fn`, no claimed source, no cap), or when the chain itself
    /// failed to produce a hit. In every non-`Some` case the caller
    /// pushes the hash to `missing` per the existing batch contract.
    ///
    /// **Cap check is owned by the substrate.** Per
    /// the named-capability-mapping ruling, the consult cap
    /// maps to `(system/substitute/sources, consult, resource)` and is
    /// enforced by `ChainConsultHook` via `entity_capability::
    /// check_permission`. CONTENT just plumbs through the caller's
    /// capability + resource target.
    async fn try_substitute_resolve(
        &self,
        hash: &Hash,
        claimed_source: Option<&Hash>,
        ctx: &HandlerContext,
    ) -> Option<Entity> {
        let resolver = self.miss_resolver.as_ref()?;
        let execute_fn = ctx.execute_fn.as_ref()?;
        match resolver
            .resolve_miss(
                hash,
                claimed_source,
                ctx.caller_capability.as_ref(),
                ctx.resource_target.as_ref(),
                execute_fn,
            )
            .await
        {
            MissOutcome::Resolved(entity) => Some(entity),
            MissOutcome::NotResolved => None,
        }
    }

    fn handle_ingest(&self, ctx: &HandlerContext) -> HandlerResult {
        if !has_resource(ctx) {
            return path_required(
                "system/content:ingest requires a resource field naming the namespace path",
            );
        }
        let params: Value = match ciborium::from_reader(ctx.params.data.as_slice()) {
            Ok(v) => v,
            Err(e) => return bad_request("invalid_params", &format!("cbor: {}", e)),
        };
        let envelope = params.get("envelope").cloned();
        let entity_v = params.get("entity").cloned();
        let env_present = !matches!(envelope, None | Some(Value::Null));
        let ent_present = !matches!(entity_v, None | Some(Value::Null));
        match (env_present, ent_present) {
            (true, true) => {
                return bad_request("ambiguous_input", "specify envelope or entity, not both")
            }
            (false, false) => {
                return bad_request("missing_input", "specify envelope or entity")
            }
            _ => {}
        }

        // Build the namespace URI used for §6.4.2 binding writes.
        //
        // **Source: `resource_target.targets[0]`, not `pattern + suffix`.**
        //
        // The cap-system already guards that the resource names the
        // intended content namespace (validated against the caller's
        // grant). It is also the canonical authority for the ingest
        // location across cohort impls (Go's `ext/content/handler.go`
        // and Python's reference both take the namespace from the
        // resource). The dispatcher's `pattern + suffix` works when
        // the EXECUTE URI carries the namespace segment explicitly
        // (e.g., `system/content/public:ingest`), but probe-ingest
        // and other cohort harnesses use the bare URI
        // `system/content:ingest` + `resource_target` to name the
        // namespace — leaving suffix empty and binding under the
        // wrong path. Resource-driven is the wire-correct read.
        //
        // (We've already gated entry with `has_resource(ctx)` above,
        // so unwrapping the first target is safe.)
        let namespace_uri = ctx
            .resource_target
            .as_ref()
            .and_then(|rt| rt.targets.first().cloned())
            .expect("has_resource gate guarantees targets[0]");

        if env_present {
            self.ingest_envelope(envelope.unwrap(), &namespace_uri)
        } else {
            self.ingest_entity(entity_v.unwrap(), &namespace_uri)
        }
    }

    /// Write the CONTENT §6.4.2 Hash Tree Presence binding for `h`
    /// under `namespace_uri`. Arch ruling 1b5c125 §2.3 — the spec MUST
    /// that closes the cohort-wide gap. No-op when no LocationIndex
    /// has been wired (legacy call sites).
    ///
    /// **Hex format: 66-char (algorithm byte + digest) per ruling §5 B**
    /// V7 §3.5 defines a hash on the wire as the full
    /// 33-byte `[algorithm || digest]` payload; the binding leaf MUST
    /// use the same encoding so cross-impl URL paths / leaf keys /
    /// ETags all reconcile. Earlier 64-char (digest-only) leaves were
    /// Rust + Go's regression; Python had it right from the start.
    fn write_namespace_binding(&self, namespace_uri: &str, h: &Hash) {
        if let Some(ref index) = self.location_index {
            let hex_h = hex_encode_hash(h);
            let path = format!("{}/{}", namespace_uri, hex_h);
            index.set(&path, *h);
        }
    }

    fn ingest_envelope(&self, envelope: Value, namespace_uri: &str) -> HandlerResult {
        // The envelope value here is the in-params envelope shape: a map
        // with optional `root` (inline core/entity map) and optional
        // `included` (map of {content_hash → entity}). We store root +
        // every included entry, validating each included entity's hash
        // matches its key.
        let mut count: u64 = 0;
        let root_v = envelope.get("root").cloned();
        let root_entity_opt = match &root_v {
            None | Some(Value::Null) => None,
            Some(v) => match decode_core_entity(v) {
                Ok(e) => Some(e),
                Err(msg) => return bad_request("invalid_envelope", &msg),
            },
        };

        let root_hash = if let Some(ref root) = root_entity_opt {
            let h = match self.content_store.put(root.clone()) {
                Ok(h) => h,
                Err(e) => return bad_request("store_failed", &e.to_string()),
            };
            // §6.4.2 — Hash Tree Presence binding (arch ruling §2.3).
            self.write_namespace_binding(namespace_uri, &h);
            count += 1;
            h
        } else {
            // No root in envelope → result.root_hash is the zero hash.
            // Spec doesn't define this corner explicitly; mirror Go's
            // posture (return the zero hash, count from included).
            Hash::zero()
        };

        if let Some(included_map) = envelope.get("included").and_then(|v| v.as_map().cloned()) {
            for (key, ent_v) in &included_map {
                let key_hash = match decode_hash_record(key) {
                    Ok(h) => h,
                    Err(msg) => {
                        return bad_request(
                            "invalid_envelope",
                            &format!("included key: {}", msg),
                        )
                    }
                };
                let entity = match decode_core_entity(ent_v) {
                    Ok(e) => e,
                    Err(msg) => {
                        return bad_request(
                            "invalid_envelope",
                            &format!("included entity: {}", msg),
                        )
                    }
                };
                let actual = entity.content_hash;
                if actual != key_hash {
                    return bad_request(
                        "hash_mismatch",
                        "included entity hash does not match key",
                    );
                }
                if let Err(e) = self.content_store.put(entity) {
                    return bad_request("store_failed", &e.to_string());
                }
                // §6.4.2 — Hash Tree Presence binding for each included.
                self.write_namespace_binding(namespace_uri, &key_hash);
                count += 1;
            }
        }

        let result_data = encode_ingest_result(root_entity_opt.as_ref(), &root_hash, count);
        let result = match Entity::new("system/content/ingest-result", result_data) {
            Ok(e) => e,
            Err(e) => return bad_request("encode_failed", &e.to_string()),
        };
        HandlerResult::ok(result)
    }

    fn ingest_entity(&self, entity_v: Value, namespace_uri: &str) -> HandlerResult {
        let entity = match decode_core_entity(&entity_v) {
            Ok(e) => e,
            Err(msg) => return bad_request("invalid_entity", &msg),
        };
        let entity_hash = entity.content_hash;
        if let Err(e) = self.content_store.put(entity) {
            return bad_request("store_failed", &e.to_string());
        }
        // §6.4.2 — Hash Tree Presence binding (arch ruling §2.3).
        self.write_namespace_binding(namespace_uri, &entity_hash);
        // Entity mode: result.root is absent (no wrapper to pass through).
        let result_data = encode_ingest_result(None, &entity_hash, 1);
        let result = match Entity::new("system/content/ingest-result", result_data) {
            Ok(e) => e,
            Err(e) => return bad_request("encode_failed", &e.to_string()),
        };
        HandlerResult::ok(result)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for SystemContentHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "get" => Ok(self.handle_get(ctx).await),
            "ingest" => Ok(self.handle_ingest(ctx)),
            other => Ok(bad_request(
                "unknown_operation",
                &format!("system/content does not support {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "content"
    }

    fn operations(&self) -> &[&str] {
        &["get", "ingest"]
    }
}

// ---------------------------------------------------------------------------
// Encoders
// ---------------------------------------------------------------------------

/// Approximate the wire cost of adding `entity` to an `included` map
/// entry, in bytes. The cost has three components:
///
/// - 33-byte hash bstr (CBOR algorithm-byte || 32-byte digest)
/// - core/entity map framing: `{type: text, data: bstr}` → ~10 bytes
///   of CBOR overhead plus the type string and data payload sizes
/// - small per-entry padding (CBOR map entry framing in the outer
///   `included` map) — folded into the 32-byte constant below
///
/// Slightly overestimates by design — the budget-MUST is one-sided
/// (better to leave headroom than overflow the frame). Exact encoding
/// would require pre-serializing each entity, doubling the cost of a
/// `get` call.
fn included_entry_cost(entity: &Entity) -> u64 {
    let type_len = entity.entity_type.len() as u64;
    let data_len = entity.data.len() as u64;
    // 33 (hash key) + 32 (entry framing + map overhead) + type + data
    65u64.saturating_add(type_len).saturating_add(data_len)
}

fn encode_content_response(found: &[Hash], missing: &[Hash]) -> Vec<u8> {
    let found_arr = Value::Array(found.iter().map(hash_to_bstr).collect());
    let missing_arr = Value::Array(missing.iter().map(hash_to_bstr).collect());
    entity_ecf::to_ecf(&Value::Map(vec![
        (entity_ecf::text("found"), found_arr),
        (entity_ecf::text("missing"), missing_arr),
    ]))
}

fn encode_ingest_result(root: Option<&Entity>, root_hash: &Hash, count: u64) -> Vec<u8> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(3);
    if let Some(r) = root {
        // Inline as a core/entity map: {type, data, content_hash}.
        // The data field carries the raw CBOR bytes the entity's data
        // already holds, so we decode them back into a Value for the
        // inline shape (the result is itself ECF-encoded below).
        let data_v: Value = ciborium::from_reader(r.data.as_slice())
            .unwrap_or(Value::Map(vec![]));
        let h = r.content_hash;
        let inline = Value::Map(vec![
            (entity_ecf::text("type"), entity_ecf::text(&r.entity_type)),
            (entity_ecf::text("data"), data_v),
            (entity_ecf::text("content_hash"), hash_to_bstr(&h)),
        ]);
        entries.push((entity_ecf::text("root"), inline));
    }
    entries.push((entity_ecf::text("root_hash"), hash_to_bstr(root_hash)));
    entries.push((
        entity_ecf::text("ingested_count"),
        Value::Integer(count.into()),
    ));
    entity_ecf::to_ecf(&Value::Map(entries))
}

/// Render a `Hash` as the canonical 33-byte CBOR bstr (algorithm ||
/// digest) per ENTITY-NATIVE-TYPE-SYSTEM §4.5. `system/hash` extends
/// `primitive/bytes` — single fields, array elements, and `included`
/// map keys all use this form.
fn hash_to_bstr(h: &Hash) -> Value {
    Value::Bytes(h.to_bytes())
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

fn decode_hash_record(value: &Value) -> Result<Hash, String> {
    let bytes = value
        .as_bytes()
        .ok_or_else(|| "hash entry not a bstr".to_string())?;
    Hash::from_bytes(bytes).map_err(|e| e.to_string())
}

/// Decode an inline `core/entity` value (`{type, data, content_hash?}`)
/// back into a typed `Entity`. We re-encode `data` to CBOR bytes to
/// preserve byte fidelity for hashing.
fn decode_core_entity(value: &Value) -> Result<Entity, String> {
    let m = value.as_map().ok_or_else(|| "entity not a map".to_string())?;
    let mut etype: Option<String> = None;
    let mut edata: Option<Value> = None;
    for (k, v) in m {
        match k.as_text() {
            Some("type") => etype = v.as_text().map(String::from),
            Some("data") => edata = Some(v.clone()),
            _ => {}
        }
    }
    let etype = etype.ok_or_else(|| "entity missing type".to_string())?;
    let edata = edata.unwrap_or(Value::Map(vec![]));
    let data_bytes = entity_ecf::to_ecf(&edata);
    Entity::new(&etype, data_bytes).map_err(|e| e.to_string())
}

fn has_resource(ctx: &HandlerContext) -> bool {
    ctx.resource_target
        .as_ref()
        .map(|rt| !rt.targets.is_empty())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Result helpers
// ---------------------------------------------------------------------------

fn path_required(message: &str) -> HandlerResult {
    bad_request("path_required", message)
}

fn bad_request(code: &str, message: &str) -> HandlerResult {
    // `system/protocol/error` data uses `{code, message}` per
    // V7 §3.5 — Go's `ErrorData.Code` and Python's equivalent both
    // read the `code` field. The Rust attestation/identity handlers
    // use the same shape.
    let data = entity_ecf::to_ecf(&Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    let err = Entity::new("system/protocol/error", data).expect("error entity");
    HandlerResult::error(STATUS_BAD_REQUEST, err)
}

/// Lowercase hex encoder for the **full 33-byte wire hash** —
/// `algorithm_byte || digest`. Per ruling §5 B the
/// §6.4.2 binding leaf MUST use the same 66-hex form as the
/// http-poll URL and ETag so cross-impl URLs and lookups reconcile.
fn hex_encode_hash(h: &Hash) -> String {
    let wire = h.to_bytes();
    let mut s = String::with_capacity(wire.len() * 2);
    for b in &wire {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

