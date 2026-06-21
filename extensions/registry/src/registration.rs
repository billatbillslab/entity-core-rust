//! Peer-issued live registration (EXTENSION-REGISTRY §6a.9).
//!
//! Curated registration (§6a.8) is the operator signing bindings by hand
//! ([`crate::peer_issued`] reads + verifies them). **Live** registration lets a
//! *publisher* self-register against a registry that runs this handler. A
//! registry is just a peer (§1 position 4); running `system/registry/peer-issued`
//! is what makes it a *live* registry rather than a curated/static one.
//!
//! The handler serves three ops:
//! - `register-request` — admit (or queue/reject) a publisher's self-signed
//!   claim, then sign + publish the binding with `K_registry` (§6a.8 act).
//! - `revoke-request` — emit a registry-signed §3.1 revocation.
//! - `renew-request` — issue a successor binding (supersedes-chain) with a new
//!   TTL.
//!
//! Two proof layers gate `register-request` (§6a.9.1):
//! - **Layer 1 — peer-id control (always):** the request carries a
//!   `system/signature` by `target_peer_id` over the request's `content_hash`
//!   (V7 §5.2). This proves the requester holds the key they are binding the
//!   name to — no one can register *someone else's* peer-id.
//! - **Layer 2 — name entitlement (policy):** the registry-local
//!   [`IssuerPolicyData`] mode (`open` / `allowlist` / `manual`) decides whether
//!   *this* requester may have *this* name. `domain-control` is DEFERRED (§6a.10).
//!
//! Replay defense: a per-requester seen-`nonce` marker plus an `issued_at`
//! freshness window (§6a.9). Ed25519-only, consistent with the resolve-side pin
//! (spec-problems **P5**).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_crypto::{IdentityKeypair, Keypair, PeerId};
use entity_ecf::{text, Value};
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_CONFLICT,
    STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_NOT_SUPPORTED,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::SignatureData;

use crate::data::{
    decode_map, get_field, normalize_name, validate_name_safety, BindingData, IssuerPolicyData,
    RegisterRequestData, RevocationData, KIND_PEER_ISSUED, MODE_ALLOWLIST, MODE_DOMAIN_CONTROL,
    MODE_MANUAL, MODE_OPEN,
};
use crate::log::now_ms;
use crate::resolver::{find_binding_signature, glob_match, peer_pubkey_from_entity};
use crate::result::{error, hash_result, status_result};
use crate::{
    binding_body_path, by_name_pointer_path, issuer_policy_path, register_nonce_path,
    revocation_by_target_path, revocation_prefix, signature_pointer_path,
};

/// Reject a request whose `issued_at` is older than this (replay-window floor).
const REGISTER_STALE_AFTER_MS: u64 = 600_000; // 10 min
/// Tolerate this much clock skew on a future-dated `issued_at`.
const REGISTER_FUTURE_SKEW_MS: u64 = 120_000; // 2 min

/// `system/registry/peer-issued` handler — the live-registration surface.
pub struct RegisterRequestHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    peer_id: String,
    signer: IdentityKeypair,
    qualified_pattern: String,
}

impl RegisterRequestHandler {
    /// `local_peer_id` is the registry's own peer-id; `signer` is `K_registry`
    /// (the local identity), held in-process to sign issued bindings — the
    /// operator's own peer signing its own bindings, never exported.
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        signer: IdentityKeypair,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/registry/peer-issued", local_peer_id);
        Self {
            content_store,
            location_index,
            peer_id: local_peer_id,
            signer,
            qualified_pattern,
        }
    }

    fn load_policy(&self) -> IssuerPolicyData {
        self.location_index
            .get(&issuer_policy_path(&self.peer_id))
            .and_then(|h| self.content_store.get(&h))
            .and_then(|e| IssuerPolicyData::from_entity(&e).ok())
            .unwrap_or_default()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for RegisterRequestHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "register-request" => Ok(self.handle_register(ctx)),
            "revoke-request" => Ok(self.handle_revoke(ctx)),
            "renew-request" => Ok(self.handle_renew(ctx)),
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown peer-issued op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "registry-peer-issued"
    }

    fn operations(&self) -> &[&str] {
        &["register-request", "revoke-request", "renew-request"]
    }
}

impl RegisterRequestHandler {
    // -------------------------------------------------------------------
    // §6a.9 :register-request
    // -------------------------------------------------------------------
    fn handle_register(&self, ctx: &HandlerContext) -> HandlerResult {
        // `ctx.params` IS the register-request entity; its content_hash is what
        // the requester signed (layer-1).
        let req = match RegisterRequestData::from_entity(&ctx.params) {
            Ok(r) => r,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let request_hash = ctx.params.content_hash;

        // §6.3 name-path safety (NFC, no '/', no control chars).
        if let Err(reason) = validate_name_safety(&req.name) {
            return error(STATUS_BAD_REQUEST, "bind_invalid_name", &reason);
        }

        // Layer 1 — peer-id control: a system/signature by `target_peer_id` over
        // the request hash (REG-REGISTER-PROOF-1). Always required.
        if !self.verify_layer1(&request_hash, &req.target_peer_id, &ctx.included) {
            return error(
                STATUS_FORBIDDEN,
                "invalid_signature",
                "request not signed by target_peer_id (layer-1 ownership proof failed)",
            );
        }

        // Replay defense — freshness window + per-requester seen-nonce
        // (REG-REGISTER-REPLAY-1).
        let now = now_ms();
        if req.issued_at > now.saturating_add(REGISTER_FUTURE_SKEW_MS)
            || now > req.issued_at.saturating_add(REGISTER_STALE_AFTER_MS)
        {
            return error(
                STATUS_FORBIDDEN,
                "stale_request",
                "issued_at outside the accepted freshness window",
            );
        }
        let nonce_path = register_nonce_path(&self.peer_id, &req.target_peer_id, &req.nonce);
        if self.location_index.get(&nonce_path).is_some() {
            return error(STATUS_CONFLICT, "replay", "nonce already seen for this requester");
        }

        // Layer 2 — issuer-policy admission (§6a.9.1).
        let policy = self.load_policy();
        // name_constraints bounds which names the registry will issue, in any mode.
        if let Some(glob) = &policy.name_constraints {
            if !glob_match(glob, &req.name) {
                return error(
                    STATUS_FORBIDDEN,
                    "not_entitled",
                    "name outside the registry's name_constraints",
                );
            }
        }
        let norm = normalize_name(&req.name, "none");
        match policy.mode.as_str() {
            MODE_OPEN => {
                // First-come-first-serve: only the name-taken check gates.
                if self.location_index.get(&by_name_pointer_path(&self.peer_id, &norm)).is_some() {
                    return error(STATUS_CONFLICT, "name_taken", "name already bound");
                }
            }
            MODE_ALLOWLIST => {
                let allowed = policy
                    .allowlist
                    .as_ref()
                    .map(|a| a.iter().any(|p| p == &req.target_peer_id))
                    .unwrap_or(false);
                if !allowed {
                    return error(
                        STATUS_FORBIDDEN,
                        "not_entitled",
                        "target_peer_id not in the registry allowlist",
                    );
                }
                if self.location_index.get(&by_name_pointer_path(&self.peer_id, &norm)).is_some() {
                    return error(STATUS_CONFLICT, "name_taken", "name already bound");
                }
            }
            MODE_MANUAL => {
                // Queue for out-of-band operator approval. Record the nonce so a
                // resubmission of the *same* request can't double-queue; the
                // pending request body is content-addressable for review.
                let _ = self.content_store.put(ctx.params.clone());
                self.location_index.set(&nonce_path, request_hash);
                return status_result(vec![(text("status"), text("pending_review"))]);
            }
            MODE_DOMAIN_CONTROL => {
                // DEFERRED — the DNS-proof challenge format co-designs with the
                // web-native dns-txt / well_known_url backends (§6a.10).
                return error(
                    STATUS_NOT_SUPPORTED,
                    "unsupported_mode",
                    "domain-control registration is not yet implemented",
                );
            }
            other => {
                return error(
                    STATUS_BAD_REQUEST,
                    "unknown_policy_mode",
                    &format!("unknown issuer-policy mode: {}", other),
                );
            }
        }

        // Approved — record the nonce, then sign + publish (the §6a.8 act).
        self.location_index.set(&nonce_path, request_hash);
        let ttl = req.requested_ttl.or(policy.default_ttl);
        match self.issue_binding(&norm, &req.target_peer_id, req.transports, ttl, None) {
            Ok(binding_hash) => hash_result("binding_hash", binding_hash),
            Err(result) => result,
        }
    }

    // -------------------------------------------------------------------
    // §6a.9 :revoke-request — registry-signed §3.1 revocation
    // -------------------------------------------------------------------
    fn handle_revoke(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let binding_hash = match get_field(&map, "binding_hash")
            .and_then(|v| v.as_bytes())
            .and_then(|b| Hash::from_bytes(b).ok())
        {
            Some(h) => h,
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "binding_hash required"),
        };
        let reason = get_field(&map, "reason")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());

        let rev = RevocationData {
            revokes: binding_hash,
            revoked_at: now_ms(),
            reason,
        };
        let rev_entity = match rev.to_entity() {
            Ok(e) => e,
            Err(e) => return error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()),
        };
        let rev_hash = rev_entity.content_hash;
        if let Err(e) = self.content_store.put(rev_entity) {
            return error(STATUS_BAD_REQUEST, "store_failed", &e.to_string());
        }
        // Registry-signed (peer-issued revocations MUST verify against K_registry,
        // §2.3 / §6a.6) at the invariant-pointer over the revocation's own hash.
        if let Err(result) = self.sign_and_publish(&rev_hash) {
            return result;
        }
        // Own-hash-keyed pointer (the resolve-side scan reads this) + the §6a.6
        // by-target index.
        self.location_index.set(
            &format!("{}{}", revocation_prefix(&self.peer_id), rev_hash.to_hex()),
            rev_hash,
        );
        self.location_index
            .set(&revocation_by_target_path(&self.peer_id, &binding_hash), rev_hash);
        status_result(vec![
            (text("revoked"), Value::Bool(true)),
            (text("revocation"), Value::Bytes(rev_hash.to_bytes().to_vec())),
        ])
    }

    // -------------------------------------------------------------------
    // §6a.9 :renew-request — successor binding (supersedes-chain), new TTL
    // -------------------------------------------------------------------
    fn handle_renew(&self, ctx: &HandlerContext) -> HandlerResult {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()),
        };
        let binding_hash = match get_field(&map, "binding_hash")
            .and_then(|v| v.as_bytes())
            .and_then(|b| Hash::from_bytes(b).ok())
        {
            Some(h) => h,
            None => return error(STATUS_BAD_REQUEST, "invalid_params", "binding_hash required"),
        };
        let new_ttl = get_field(&map, "ttl")
            .and_then(|v| v.as_integer())
            .and_then(|i| u64::try_from(i).ok());

        let prev = match self
            .content_store
            .get(&binding_hash)
            .and_then(|e| BindingData::from_entity(&e).ok())
        {
            Some(p) => p,
            None => return error(STATUS_NOT_FOUND, "not_found", "no such binding"),
        };
        let norm = normalize_name(&prev.name, "none");
        match self.issue_binding(
            &norm,
            &prev.target_peer_id,
            prev.transports,
            new_ttl,
            Some(binding_hash),
        ) {
            Ok(h) => hash_result("binding_hash", h),
            Err(result) => result,
        }
    }

    // -------------------------------------------------------------------
    // Layer-1 verification + the §6a.8 sign+publish act
    // -------------------------------------------------------------------

    /// Layer-1 proof: a `system/signature` (in `included` or at the invariant
    /// pointer) targeting `request_hash`, whose signer's identity derives to
    /// `target_peer_id`, and which crypto-verifies. Ed25519-only (P5).
    fn verify_layer1(
        &self,
        request_hash: &Hash,
        target_peer_id: &str,
        included: &HashMap<Hash, entity_entity::Entity>,
    ) -> bool {
        let sig = match find_binding_signature(
            request_hash,
            &self.content_store,
            &self.location_index,
            included,
        ) {
            Some(s) => s,
            None => return false,
        };
        let signer_entity = match included
            .get(&sig.signer)
            .cloned()
            .or_else(|| self.content_store.get(&sig.signer))
        {
            Some(e) => e,
            None => return false,
        };
        let pubkey = match peer_pubkey_from_entity(&signer_entity) {
            Some(pk) => pk,
            None => return false,
        };
        // The proof: the signer's key must derive to the claimed target_peer_id.
        if PeerId::from_public_key(&pubkey).as_str() != target_peer_id {
            return false;
        }
        Keypair::verify(&pubkey, &request_hash.to_bytes(), &sig.signature).is_ok()
    }

    /// `registry-issue-binding` (§6a.8): build the binding body, sign its hash
    /// with `K_registry`, and publish body + invariant-pointer signature +
    /// by-name pointer. `supersedes` threads the renew chain. Returns the
    /// binding hash, or an error `HandlerResult` to surface verbatim. (The
    /// `Err` carries a `HandlerResult` by design — it's the rejection entity the
    /// caller forwards untouched, not a hot-path value.)
    #[allow(clippy::result_large_err)]
    fn issue_binding(
        &self,
        name_norm: &str,
        target_peer_id: &str,
        transports: Vec<Value>,
        ttl: Option<u64>,
        supersedes: Option<Hash>,
    ) -> Result<Hash, HandlerResult> {
        let binding = BindingData {
            name: name_norm.to_string(),
            kind: KIND_PEER_ISSUED.into(),
            target_peer_id: target_peer_id.to_string(),
            transports,
            issued_at: now_ms(),
            ttl,
            supersedes,
            issuer_attestation: None,
            metadata: None,
        };
        let entity = binding
            .to_entity()
            .map_err(|e| error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()))?;
        let binding_hash = entity.content_hash;
        self.content_store
            .put(entity)
            .map_err(|e| error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()))?;
        self.sign_and_publish(&binding_hash)?;
        // §3 universal body path + §6a.3 by-name index.
        self.location_index
            .set(&binding_body_path(&self.peer_id, &binding_hash), binding_hash);
        self.location_index
            .set(&by_name_pointer_path(&self.peer_id, name_norm), binding_hash);
        Ok(binding_hash)
    }

    /// Sign `target` with `K_registry` and publish the signature at the
    /// invariant-pointer `system/signature/{hex(target)}`, plus the registry's
    /// own `system/peer` entity so verifiers can resolve `sig.signer`.
    #[allow(clippy::result_large_err)]
    fn sign_and_publish(&self, target: &Hash) -> Result<(), HandlerResult> {
        let peer_entity = self
            .signer
            .peer_entity()
            .map_err(|e| error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()))?;
        let _ = self.content_store.put(peer_entity);

        let sig = SignatureData {
            target: *target,
            signer: self.signer.peer_identity_hash(),
            algorithm: self.signer.key_type().label().to_string(),
            signature: self.signer.sign(&target.to_bytes()),
        };
        let sig_entity = sig
            .to_entity()
            .map_err(|e| error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string()))?;
        let sig_hash = sig_entity.content_hash;
        self.content_store
            .put(sig_entity)
            .map_err(|e| error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()))?;
        self.location_index
            .set(&signature_pointer_path(&self.peer_id, target), sig_hash);
        Ok(())
    }
}
