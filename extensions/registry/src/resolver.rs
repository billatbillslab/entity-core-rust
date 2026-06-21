//! Meta-resolver substrate (§2 / §4) — the `system/registry` handler.
//!
//! Ops: `:resolve(name, [hints]) → ResolutionResult` and
//! `:invalidate-cache(name | null) → ()`. The resolve algorithm (§4.1):
//!
//! 1. **Pinned bindings** override everything → synthesized result (§4.1.2).
//! 2. **`name_format_dispatch`** narrows the chain (POSIX shell-glob); the
//!    primary privacy mechanism — backends without a dispatch entry match-all.
//! 3. **Filtered chain in priority order** — first validated hit wins.
//! 4. else **`chain_exhausted`** (fail-closed; no silent fallback).
//!
//! Validation = trust-anchor receiver policy + revocation honor + (for signed,
//! non-local-name/non-self-certifying kinds) signature verification. v1 ships the
//! local-name backend as the only concrete chain backend; other `backend_kind`s
//! skip-with-warning (§4.2). The signature primitive
//! ([`verify_binding_signature`]) is provided for backends shipped separately.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_crypto::Keypair;
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::SignatureData;

use crate::data::{
    decode_map, get_field, BindingData, ResolutionResult, ResolverConfigData, RevocationData,
    KIND_LOCAL_NAME, KIND_SELF_CERTIFYING, TRUST_OUT_OF_BAND,
};
use crate::local_name::{load_local_name_config, resolve_one};
use crate::result::{error, status_result};
use crate::log::ResolutionLog;
use crate::{
    resolver_config_path, BACKEND_KIND_LOCAL_NAME, BACKEND_KIND_PEER_ISSUED,
};

/// `system/registry` meta-resolver handler.
pub struct RegistryHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    peer_id: String,
    qualified_pattern: String,
    log: Arc<ResolutionLog>,
}

impl RegistryHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        log: Arc<ResolutionLog>,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/registry", local_peer_id);
        Self {
            content_store,
            location_index,
            peer_id: local_peer_id,
            qualified_pattern,
            log,
        }
    }

    fn load_config(&self) -> ResolverConfigData {
        self.location_index
            .get(&resolver_config_path(&self.peer_id))
            .and_then(|h| self.content_store.get(&h))
            .and_then(|e| ResolverConfigData::from_entity(&e).ok())
            .unwrap_or_else(|| self.default_local_name_only())
    }

    /// Default when no resolver-config exists: a single local-name backend at
    /// priority 0 (the §10 "local-name-only" deployment), so the local store works
    /// out of the box. The seed-policy MAY overwrite this with a richer config.
    fn default_local_name_only(&self) -> ResolverConfigData {
        use crate::data::ResolverChainEntry;
        ResolverConfigData {
            resolver_chain: vec![ResolverChainEntry {
                backend_kind: BACKEND_KIND_LOCAL_NAME.into(),
                backend_id: self.peer_id.clone(),
                priority: 0,
                accepted_trust_anchors: Vec::new(),
                hints: None,
            }],
            ..Default::default()
        }
    }

    /// §4.1 meta_resolve.
    fn meta_resolve(&self, name: &str, config: &ResolverConfigData) -> ResolutionResult {
        // Step 1: pinned bindings override everything.
        if let Some(pin) = config.pinned_bindings.iter().find(|p| p.name == name) {
            return self.synthesize_pin(pin);
        }

        // Step 2: name_format_dispatch filter (privacy mechanism). A backend
        // kind that appears in ANY dispatch rule is "restricted" — consulted
        // only when a rule whose backend_kinds contains it matches the name.
        // Kinds appearing in no rule are match-all.
        let restricted: std::collections::HashSet<&str> = config
            .name_format_dispatch
            .iter()
            .flat_map(|r| r.backend_kinds.iter().map(|s| s.as_str()))
            .collect();
        let allowed = |kind: &str| -> bool {
            if !restricted.contains(kind) {
                return true;
            }
            config.name_format_dispatch.iter().any(|r| {
                r.backend_kinds.iter().any(|k| k == kind) && glob_match(&r.pattern, name)
            })
        };

        // Step 3: filtered chain in ascending priority order; first validated hit.
        let mut chain: Vec<&crate::data::ResolverChainEntry> = config
            .resolver_chain
            .iter()
            .filter(|e| allowed(&e.backend_kind))
            .collect();
        chain.sort_by_key(|e| e.priority);

        for entry in chain {
            let candidate = match entry.backend_kind.as_str() {
                BACKEND_KIND_LOCAL_NAME => {
                    let pcfg =
                        load_local_name_config(&self.content_store, &self.location_index, &self.peer_id);
                    resolve_one(
                        &self.content_store,
                        &self.location_index,
                        &self.peer_id,
                        &pcfg,
                        name,
                    )
                }
                BACKEND_KIND_PEER_ISSUED => crate::peer_issued::resolve_one(
                    &self.content_store,
                    &self.location_index,
                    entry,
                    name,
                ),
                other => {
                    // Unknown / unsupported backend kind in v1 — skip-with-warning
                    // (§4.2 forward-compat). Backends ship in their own proposals.
                    tracing::warn!(backend_kind = other, "registry: skipping unsupported backend");
                    None
                }
            };
            let Some(result) = candidate else { continue };
            if !result.is_resolved() {
                continue;
            }
            // Receiver-policy: trust-anchor must pass accepted_trust_anchors.
            if !entry.accepted_trust_anchors.is_empty() {
                let ok = result
                    .trust_anchor
                    .as_deref()
                    .map(|ta| entry.accepted_trust_anchors.iter().any(|a| a == ta))
                    .unwrap_or(false);
                if !ok {
                    continue;
                }
            }
            // Revocation honor (§3.1 / §6.6): exclude + advance if revoked.
            if let Some(binding_hash) = result.binding {
                if self.is_revoked(binding_hash) {
                    continue;
                }
            }
            return result;
        }
        ResolutionResult::chain_exhausted()
    }

    /// §4.1.2 — deterministic synthesized result for a pinned binding. The
    /// synthetic `out-of-band` binding entity is stored so its hash resolves
    /// (inspectability invariant); `issued_at: 0` keeps the hash deterministic.
    fn synthesize_pin(&self, pin: &crate::data::PinnedBinding) -> ResolutionResult {
        let synthetic = BindingData {
            name: pin.name.clone(),
            kind: "out-of-band".into(),
            target_peer_id: pin.target_peer_id.clone(),
            transports: Vec::new(),
            issued_at: 0,
            ttl: None,
            supersedes: None,
            issuer_attestation: None,
            metadata: None,
        };
        let binding_hash = match synthetic.to_entity() {
            Ok(e) => {
                let h = e.content_hash;
                let _ = self.content_store.put(e);
                Some(h)
            }
            Err(_) => None,
        };
        ResolutionResult {
            status: crate::data::STATUS_RESOLVED.into(),
            binding: binding_hash,
            peer_id: Some(pin.target_peer_id.clone()),
            transports: Vec::new(),
            attestations: Vec::new(),
            trust_anchor: Some(TRUST_OUT_OF_BAND.into()),
            ttl: None,
            neg_ttl: None,
            backend_id: Some("pinned".into()),
        }
    }

    /// Look for a `system/registry/revocation` entity targeting `binding_hash`.
    ///
    /// Revocation entities are stored at `system/registry/revocation/{hex}`
    /// keyed by the **revocation entity's own content hash** (cohort
    /// convention — Go `RevocationStoragePath`, validate-peer v6), NOT by the
    /// binding they revoke. So discovery is a **scan** of the revocation
    /// subtree, matching on the `revokes:` field — not an O(1) lookup keyed by
    /// the binding hash (the spec pins the entity type + signature carriage,
    /// not a binding-keyed path — see docs/SPEC-AMBIGUITIES.md §3.1 carve-out).
    ///
    /// A local-name binding is excluded on presence of any type-valid
    /// revocation: the local store is itself the trust source (§6.3 carve-out,
    /// same as the local-name binding), so an unsigned local revocation suffices.
    /// Signed kinds (DID-web, etc.) would additionally require a same-authority
    /// signed revocation.
    fn is_revoked(&self, binding_hash: Hash) -> bool {
        let prefix = format!("/{}/system/registry/revocation/", self.peer_id);
        self.location_index.list(&prefix).into_iter().any(|entry| {
            self.content_store
                .get(&entry.hash)
                .and_then(|e| RevocationData::from_entity(&e).ok())
                .map(|rev| rev.revokes == binding_hash)
                .unwrap_or(false)
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for RegistryHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "resolve" => Ok(self.handle_resolve(ctx)),
            "invalidate-cache" => Ok(self.handle_invalidate_cache(ctx)),
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown registry op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "registry"
    }

    fn operations(&self) -> &[&str] {
        &["resolve", "invalidate-cache"]
    }
}

impl RegistryHandler {
    fn handle_resolve(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let name = match get_field(&map, "name").and_then(|v| v.as_text()) {
            Some(n) => n.to_string(),
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "name required"),
        };
        let is_fallback = get_field(&map, "is_fallback_reresolve")
            .and_then(|v| match v {
                ciborium::Value::Bool(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);

        let config = self.load_config();
        let result = self.meta_resolve(&name, &config);

        // §11.2: one log entry per top-level meta_resolve; transport-fallback
        // re-resolves are NOT written (avoid hot-path write amplification).
        if !is_fallback {
            self.log.record(
                &name,
                &result.status,
                result.backend_id.clone(),
                None,
                result.binding,
                false,
            );
        }
        // §2.1 Ruling-3: return the bare `system/registry/resolution-result`
        // entity with flat data — NOT wrapped under `system/protocol/status`.
        HandlerResult {
            status: entity_handler::STATUS_OK,
            result: result.to_entity(),
            included: HashMap::new(),
        }
    }

    /// `:invalidate-cache(name | null)` — v1's resolver is stateless
    /// (re-resolves each call), so there is no positive-resolution cache to
    /// flush; returns ok. TTL-based caching is a SHOULD layered on top (§11.2).
    fn handle_invalidate_cache(&self, _ctx: &HandlerContext) -> HandlerResult {
        status_result(vec![(entity_ecf::text("invalidated"), ciborium::Value::Bool(true))])
    }
}

// ---------------------------------------------------------------------------
// Signature verification primitive (§3) — for signed (non-local-name) backends.
// ---------------------------------------------------------------------------

/// Verify a binding's authenticating `system/signature` (§3). Returns `true`
/// for self-certifying (name == target_peer_id, valid V7 §1.5 structure) and
/// local-name (user is trust source) bindings without a signature. For all
/// other kinds, locates the signature via `included` or the invariant-pointer
/// path `system/signature/{hex(binding_hash)}` and verifies it against the
/// issuer's published key.
pub fn verify_binding_signature(
    binding: &BindingData,
    binding_hash: &Hash,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    included: &HashMap<Hash, Entity>,
) -> bool {
    match binding.kind.as_str() {
        KIND_LOCAL_NAME => true,
        KIND_SELF_CERTIFYING => {
            binding.name == binding.target_peer_id
                && entity_crypto::PeerId::from(binding.target_peer_id.clone())
                    .decode()
                    .is_ok()
        }
        _ => {
            let sig = match find_binding_signature(binding_hash, content_store, location_index, included)
            {
                Some(s) => s,
                None => return false,
            };
            let pubkey = match resolve_peer_pubkey(&sig.signer, content_store) {
                Some(pk) => pk,
                None => return false,
            };
            Keypair::verify(&pubkey, &binding_hash.to_bytes(), &sig.signature).is_ok()
        }
    }
}

pub(crate) fn find_binding_signature(
    target: &Hash,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    included: &HashMap<Hash, Entity>,
) -> Option<SignatureData> {
    // (1) envelope-bundled.
    for entity in included.values() {
        if entity.entity_type == TYPE_SIGNATURE {
            if let Ok(sig) = SignatureData::from_entity(entity) {
                if &sig.target == target {
                    return Some(sig);
                }
            }
        }
    }
    // (2) invariant-pointer at .../system/signature/{target_hex}.
    let suffix = format!("system/signature/{}", target.to_hex());
    for entry in location_index.list("/") {
        if !entry.path.ends_with(&suffix) {
            continue;
        }
        if let Some(e) = content_store.get(&entry.hash) {
            if e.entity_type == TYPE_SIGNATURE {
                if let Ok(sig) = SignatureData::from_entity(&e) {
                    if &sig.target == target {
                        return Some(sig);
                    }
                }
            }
        }
    }
    None
}

pub(crate) fn resolve_peer_pubkey(
    peer_hash: &Hash,
    content_store: &Arc<dyn ContentStore>,
) -> Option<[u8; 32]> {
    peer_pubkey_from_entity(&content_store.get(peer_hash)?)
}

/// Extract the Ed25519 `public_key` digest from a `system/peer` entity (v1
/// trust-anchor floor, §6a.5 — Ed25519-only). Shared by the resolve-side
/// pin check and the registration-side layer-1 proof.
pub(crate) fn peer_pubkey_from_entity(entity: &Entity) -> Option<[u8; 32]> {
    if entity.entity_type != entity_crypto::TYPE_PEER {
        return None;
    }
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = value.as_map()?;
    let pk = map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("public_key") {
            v.as_bytes()
        } else {
            None
        }
    })?;
    pk.as_slice().try_into().ok()
}

// ---------------------------------------------------------------------------
// POSIX shell-glob matcher (§4.1 name_format_dispatch.pattern)
// ---------------------------------------------------------------------------

/// Minimal POSIX shell-glob: `*` (any run), `?` (one char), `[...]` char class
/// (with leading `!` negation). Matches against the whole string.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    glob_rec(pattern.as_bytes(), text.as_bytes())
}

fn glob_rec(mut p: &[u8], mut t: &[u8]) -> bool {
    loop {
        match p.first() {
            None => return t.is_empty(),
            Some(b'*') => {
                // Collapse consecutive stars.
                while p.first() == Some(&b'*') {
                    p = &p[1..];
                }
                if p.is_empty() {
                    return true;
                }
                // Try to match the rest at every suffix.
                for i in 0..=t.len() {
                    if glob_rec(p, &t[i..]) {
                        return true;
                    }
                }
                return false;
            }
            Some(b'?') => {
                if t.is_empty() {
                    return false;
                }
                p = &p[1..];
                t = &t[1..];
            }
            Some(b'[') => {
                if t.is_empty() {
                    return false;
                }
                match class_match(&p[1..], t[0]) {
                    Some(consumed) => {
                        p = &p[1 + consumed..];
                        t = &t[1..];
                    }
                    None => return false,
                }
            }
            Some(&c) => {
                if t.first() != Some(&c) {
                    return false;
                }
                p = &p[1..];
                t = &t[1..];
            }
        }
    }
}

/// Match `ch` against a `[...]` class starting after the `[`. Returns the
/// number of bytes consumed up to and including the closing `]`, or `None` if
/// no match / malformed.
fn class_match(spec: &[u8], ch: u8) -> Option<usize> {
    let mut i = 0;
    let negate = spec.first() == Some(&b'!');
    if negate {
        i += 1;
    }
    let mut matched = false;
    let start = i;
    while i < spec.len() {
        let c = spec[i];
        if c == b']' && i > start {
            // closing bracket
            return if matched != negate {
                Some(i + 1)
            } else {
                None
            };
        }
        // range a-z
        if i + 2 < spec.len() && spec[i + 1] == b'-' && spec[i + 2] != b']' {
            let lo = c;
            let hi = spec[i + 2];
            if ch >= lo && ch <= hi {
                matched = true;
            }
            i += 3;
        } else {
            if ch == c {
                matched = true;
            }
            i += 1;
        }
    }
    None // unterminated class
}
