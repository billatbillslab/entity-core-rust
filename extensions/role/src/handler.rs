//! `system/role` handler — all 7 ops (EXTENSION-ROLE v1.6 §4).
//!
//! Path-as-resource (V7 §3.2): every op reads its target tree path from
//! `EXECUTE.resource.targets[0]`. Params carry only the role-name
//! selector or are empty.
//!
//! **v1.6 wire-shape pins** (PROPOSAL-ROLE-V1.5-SPEC-FIXES):
//! - SI-1: `{peer_id}` segments are lowercase hex of identity-entity
//!   `system/hash`.
//! - SI-3: exclusion entity has no body `peer_id` field.
//! - SI-4: `delegate-request.context`/`.role` are `primitive/string`.
//! - SI-5: linkage entity at `system/role/{ctx}/derived-tokens/{peer}/{role}`.
//! - SI-8: `grantee` is the raw bytes of the assignee's identity hash.
//! - SI-15: re-derive emits `skipped_grantees` (RL2 fail-closed mid-cascade).
//! - SI-19: `:delegate` is local-only (`ctx.author == identity_hash`).
//! - SI-20: delegation `scope` is literal — no template substrings.
//! - SI-21: `delegate-request` has no `delegator` field.
//! - SI-22: delegation parent comes from the linkage entity.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_capability::{
    is_attenuated, CapabilityToken, GrantEntry, Granter, IdScope, PathScope,
};
use entity_crypto::IdentityKeypair;
use entity_ecf::{text, to_ecf, Value};
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_handler::{
    error_entity, Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST,
    STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OK,
};
use entity_hash::{invariant_signature_path, Hash};
use entity_store::{ContentStore, LocationIndex};
use entity_types::{
    TYPE_ROLE, TYPE_ROLE_ASSIGN_RESULT, TYPE_ROLE_EXCLUDE_RESULT,
};

use crate::data::{
    decode_grant_array_value, decode_map, field_hash, field_text, field_u64_opt,
    get_field, hex_segment, RoleAssignmentData, RoleData, RoleDerivedTokenLinkData,
    RoleExclusionData,
};
use crate::helpers::{is_excluded, resolve_grant_templates};
use crate::paths::{
    hash_from_peer_segment, parse_assignment_path, parse_exclusion_path,
    parse_role_definition_path, path_role_assignment, path_role_definition,
    path_role_derived_link, path_role_derived_token, peer_segment_from_hash,
    prefix_role_assignment, prefix_role_assignment_peer,
    prefix_role_derived_links_peer, prefix_role_derived_peer,
    ParsedAssignmentPath, ParsedExclusionPath, ParsedRoleDefPath,
};
use crate::{
    OP_ASSIGN, OP_DEFINE, OP_DELEGATE, OP_EXCLUDE, OP_RE_DERIVE, OP_UNASSIGN, OP_UNEXCLUDE,
};

/// `system/role` handler.
pub struct RoleHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
    qualified_prefix: String,
    /// Local peer's identity entity hash. Used as granter for tokens
    /// derived by the runtime path (handler is the granter; token's
    /// `parent` is the handler's own self-grant per §5.1 step 5).
    identity_hash: Hash,
    /// Local keypair for signing role-derived capability tokens.
    /// Polymorphic over key_type (v7.67 Phase 2).
    keypair: IdentityKeypair,
}

impl RoleHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        identity_hash: Hash,
        keypair: IdentityKeypair,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/role", local_peer_id);
        let qualified_prefix = format!("/{}/", local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
            qualified_prefix,
            identity_hash,
            keypair,
        }
    }

    fn qualify(&self, bare: &str) -> String {
        format!("/{}/{}", self.local_peer_id, bare)
    }

    fn resource_path(&self, ctx: &HandlerContext) -> Option<String> {
        ctx.resource_target
            .as_ref()
            .and_then(|rt| rt.targets.first().cloned())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for RoleHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            OP_ASSIGN => self.handle_assign(ctx).await,
            OP_UNASSIGN => self.handle_unassign(ctx).await,
            OP_EXCLUDE => self.handle_exclude(ctx).await,
            OP_UNEXCLUDE => self.handle_unexclude(ctx).await,
            OP_DEFINE => self.handle_define(ctx).await,
            OP_RE_DERIVE => self.handle_re_derive(ctx).await,
            OP_DELEGATE => self.handle_delegate(ctx).await,
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown role op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "role"
    }

    fn operations(&self) -> &[&str] {
        // All seven role ops per §4.1 manifest. The bootstrap manifest in
        // peer/lib.rs must mirror this slice.
        &[
            OP_ASSIGN,
            OP_UNASSIGN,
            OP_EXCLUDE,
            OP_UNEXCLUDE,
            OP_DEFINE,
            OP_RE_DERIVE,
            OP_DELEGATE,
        ]
    }
}

impl RoleHandler {
    // -------------------------------------------------------------------
    // §4.3 assign
    // -------------------------------------------------------------------

    async fn handle_assign(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // Step 1: resource decomposition (§4.3 step 1)
        let path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "ambiguous_resource",
                    "assign requires exactly one resource target (the assignment path)",
                ))
            }
        };
        let parsed = match parse_assignment_path(&path) {
            Some(p) if p.role_name.is_some() => p,
            _ => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "malformed_resource",
                    "expected system/role/{context}/assignment/{assignee}/{role_name}",
                ))
            }
        };
        let ParsedAssignmentPath {
            context,
            peer_id: assignee,
            role_name: path_role,
        } = parsed;
        let path_role = path_role.unwrap(); // validated above

        // Step 2: validate params.role and confirm it matches the path
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))
            }
        };
        let role_name = match field_text(&map, "role") {
            Ok(r) => r,
            Err(_) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "invalid_assign_request",
                    "role is required",
                ))
            }
        };
        if role_name != path_role {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "role_path_mismatch",
                "params.role must equal the role segment of the resource path",
            ));
        }

        // Step 3: resolve role definition (handler reads under its own grant)
        let role_def_path = self.qualify(&path_role_definition(&context, &role_name));
        let role_hash = match self.location_index.get(&role_def_path) {
            Some(h) => h,
            None => {
                return Ok(error(
                    STATUS_NOT_FOUND,
                    "role_not_found",
                    &format!("no role definition at {}", role_def_path),
                ))
            }
        };
        let role_entity = match self.content_store.get(&role_hash) {
            Some(e) => e,
            None => {
                return Ok(error(
                    STATUS_NOT_FOUND,
                    "role_not_found",
                    "role definition path bound but entity missing in content store",
                ))
            }
        };
        let role_def = match RoleData::from_entity(&role_entity) {
            Ok(r) => r,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "role_decode_failed",
                    &e.to_string(),
                ))
            }
        };

        // Step 4: template-resolve grants (§5.2)
        let derived_grants: Vec<GrantEntry> = role_def
            .grants
            .iter()
            .map(|g| resolve_grant_templates(g, &context, &assignee))
            .collect();

        // Step 4b: layer-2 exclusion check (§4.3 step 4b, R7 layer 2)
        if is_excluded(
            &self.location_index,
            &self.qualified_prefix,
            &context,
            &assignee,
        ) {
            return Ok(error(
                STATUS_FORBIDDEN,
                "assignee_excluded",
                "Cannot assign role to a peer in the context's exclusion subtree",
            ));
        }

        // Step 5: RL2 — caller's authority must cover the derived grants
        // (§4.3 step 5, IA10 fail-closed).
        let caller_cap = match &ctx.caller_capability {
            Some(c) => c,
            None => {
                return Ok(error(
                    STATUS_FORBIDDEN,
                    "missing_caller_capability",
                    "RL2: caller_capability required to attenuate role-derived grants",
                ))
            }
        };

        // v1.7 §5.3 / §4.3 step 5: compute the issued cap's expires_at
        // BEFORE the RL2 check so the hypothetical and the persisted cap
        // share shape ("RL2 OK at issue, chain-invalid at use" closed).
        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let parent_expires =
            ctx.handler_grant.as_ref().and_then(|c| c.expires_at);
        let role_ttl = role_metadata_ttl(&role_def.metadata);
        let cap_expires_at =
            effective_expires_at(parent_expires, role_ttl, caller_cap.expires_at, now_ms);

        let hypothetical = build_hypothetical_token(
            derived_grants.clone(),
            caller_cap,
            self.identity_hash,
            cap_expires_at,
        );
        if !is_attenuated(&hypothetical, caller_cap, &self.local_peer_id) {
            return Ok(error(
                STATUS_FORBIDDEN,
                "assigner_authority_insufficient",
                &format!(
                    "RL2: caller capability does not cover role-derived grants for {}",
                    role_name
                ),
            ));
        }

        // Step 6: assignee identity hash for grantee. Per SI-1 + SI-8 the
        // assignee path-segment IS hex of the assignee's identity-entity
        // `system/hash`; the handler reads it as raw bytes via
        // `hash_from_peer_segment` and uses that for the cap's grantee
        // field. No PeerID-to-hash resolution needed.
        //
        // PR-1 (PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS §2.4): role-derived
        // caps are ROOT caps (`parent: null`), structurally identical to the
        // startup-time L0 path per §4.5. The handler-grant `expires_at` still
        // feeds the v1.7 §5.3 MIN_DEFINED formula above (computed in step 5)
        // — only the persisted `parent` field flips to None. Use-time chain
        // validation now terminates at the role-derived cap regardless of
        // how narrow the handler grant is, which is required for non-dev
        // peers (TV-RD-NON-DEV-PEER).
        let grantee_hash = match hash_from_peer_segment(&assignee) {
            Some(h) => h,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "malformed_resource",
                    "assignee path segment must be lowercase hex of identity-entity hash (SI-1)",
                ))
            }
        };
        // SEC-18 / V7 v7.39 PR-3: reject zero-hash assignee at the role layer.
        // Zero-hash never resolves to a `system/peer` entity, so the minted cap
        // would fail chain-walk anyway (PR-3 `unresolvable_grantee` at use time).
        // Failing fast here surfaces the error to the assigner instead of leaving
        // a dud cap bound (PLAN-LIFECYCLE-INTEGRATION-VALIDATION docket §4.1
        // option (a) / Go reference).
        if grantee_hash.is_zero() {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "invalid_assign_request",
                "assignee peer_id_hex MUST NOT be a zero hash (SEC-18)",
            ));
        }

        // Step 7: persist the assignment entity
        let assignment = RoleAssignmentData {
            role: role_name.clone(),
            assigned_by: ctx.author.unwrap_or_else(Hash::zero),
            assigned_at: now_ms,
            metadata: None,
        };
        let assignment_entity = match assignment.to_entity() {
            Ok(e) => e,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "encode_failed",
                    &e.to_string(),
                ))
            }
        };
        let assignment_hash = match self.content_store.put(assignment_entity) {
            Ok(h) => h,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "store_failed",
                    &e.to_string(),
                ))
            }
        };
        let assignment_path =
            self.qualify(&path_role_assignment(&context, &assignee, &role_name));
        self.location_index.set(&assignment_path, assignment_hash);

        // Step 8: derive + persist token (§5.1) + linkage entity (SI-5).
        // PR-1: parent: None — role-derived caps are root caps.
        let token_hash = match self.derive_and_persist_token(
            &context,
            &assignee,
            &role_name,
            grantee_hash,
            derived_grants,
            None,
            cap_expires_at,
        ) {
            Ok(h) => h,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "token_derivation_failed",
                    &e,
                ))
            }
        };

        // Step 9 — PR-2 (SEC-2 atomicity, §6.6): post-issue exclusion
        // re-check + rollback. A concurrent `:exclude` may have completed
        // its layer-1 sweep between the step-4b pre-check and this point,
        // landing the exclusion entity but missing the not-yet-bound cap.
        // Re-check; if excluded, undo the assignment + cap + sig + linkage
        // bindings and return 403. See PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS
        // §3.
        if is_excluded(
            &self.location_index,
            &self.qualified_prefix,
            &context,
            &assignee,
        ) {
            self.rollback_role_derived_cap(&context, &assignee, &role_name, token_hash, true);
            self.location_index.remove(&assignment_path);
            return Ok(error(
                STATUS_FORBIDDEN,
                "assignee_excluded",
                "exclusion landed during :assign — rolled back per §6.6 atomicity",
            ));
        }

        Ok(assign_result(&assignment_path, &[token_hash]))
    }

    // -------------------------------------------------------------------
    // §4.4 unassign — remove assignment + revoke role-derived tokens (IA12)
    // -------------------------------------------------------------------

    async fn handle_unassign(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "ambiguous_resource",
                    "unassign requires the assignment path as resource",
                ))
            }
        };
        let parsed = match parse_assignment_path(&path) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "malformed_resource",
                    "expected system/role/{context}/assignment/{peer_id}[/{role_name}]",
                ))
            }
        };
        let ParsedAssignmentPath {
            context,
            peer_id: assignee,
            role_name,
        } = parsed;

        // SI-5 v1.6: per-(peer, role) revocation precision via linkage
        // entity. For a specific role: read the linkage entity, revoke
        // the linked token (V7 §5.5 mechanism), remove assignment +
        // linkage. For the all-roles form: walk both the assignment and
        // derived-tokens subtrees for this peer.
        let mut revoked: Vec<Hash> = Vec::new();
        match &role_name {
            Some(rn) => {
                let assignment_path =
                    self.qualify(&path_role_assignment(&context, &assignee, rn));
                self.location_index.remove(&assignment_path);
                if let Some(h) = self.revoke_via_linkage(&context, &assignee, rn) {
                    revoked.push(h);
                }
            }
            None => {
                // Walk all linkage entities for this peer to revoke the
                // tokens precisely; then sweep the assignment subtree.
                let link_prefix =
                    self.qualify(&prefix_role_derived_links_peer(&context, &assignee));
                for link_entry in self.location_index.list(&link_prefix) {
                    let role_seg = link_entry
                        .path
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    if let Some(h) = self.revoke_via_linkage(&context, &assignee, &role_seg) {
                        revoked.push(h);
                    }
                }
                let assn_prefix =
                    self.qualify(&prefix_role_assignment_peer(&context, &assignee));
                for entry in self.location_index.list(&assn_prefix) {
                    self.location_index.remove(&entry.path);
                }
            }
        }

        Ok(unassign_result(&path, &revoked))
    }

    /// SI-5 + IA12: read the linkage entity for `(context, peer, role)`,
    /// remove the bound role-derived cap at the R4 path, and remove the
    /// linkage entity itself. Returns the revoked cap hash if a token
    /// was actually unbound. Silent no-op if no linkage exists.
    fn revoke_via_linkage(
        &self,
        context: &str,
        peer_id_hex: &str,
        role_name: &str,
    ) -> Option<Hash> {
        let link_path =
            self.qualify(&path_role_derived_link(context, peer_id_hex, role_name));
        let link_hash = self.location_index.get(&link_path)?;
        let link_entity = match self.content_store.get(&link_hash) {
            Some(e) => e,
            None => {
                self.location_index.remove(&link_path);
                return None;
            }
        };
        let link = match RoleDerivedTokenLinkData::from_entity(&link_entity) {
            Ok(l) => l,
            Err(_) => {
                self.location_index.remove(&link_path);
                return None;
            }
        };
        let token_path = self.qualify(&path_role_derived_token(
            context,
            peer_id_hex,
            &hex_segment(&link.token_hash),
        ));
        let removed = self.location_index.remove(&token_path);
        // V7 §3.5 v7.44: the cap's signature is bound at the invariant
        // pointer path (keyed by the cap hash) — unbind it there.
        self.location_index.remove(&invariant_signature_path(
            &self.local_peer_id,
            &link.token_hash,
        ));
        self.location_index.remove(&link_path);
        removed
    }

    // -------------------------------------------------------------------
    // §4.4 exclude — write exclusion entity + layer-1 token sweep (R7 L1)
    // -------------------------------------------------------------------

    async fn handle_exclude(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "ambiguous_resource",
                    "exclude requires the exclusion path as resource",
                ))
            }
        };
        let parsed = match parse_exclusion_path(&path) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "malformed_resource",
                    "expected system/role/{context}/excluded/{peer_id}",
                ))
            }
        };
        let ParsedExclusionPath { context, peer_id } = parsed;

        // Optional reason from params (no separate request type; empty-params
        // shape is acceptable per V7 §3.2).
        let reason = match decode_map(&ctx.params.data) {
            Ok(map) => get_field(&map, "reason")
                .and_then(|v| v.as_text())
                .map(|s| s.to_string()),
            Err(_) => None,
        };

        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        // SI-3 v1.6: no peer_id body field — the path segment is the
        // canonical encoding.
        let exclusion = RoleExclusionData {
            excluded_by: ctx.author.unwrap_or_else(Hash::zero),
            excluded_at: now_ms,
            reason,
        };
        let entity = match exclusion.to_entity() {
            Ok(e) => e,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "encode_failed",
                    &e.to_string(),
                ))
            }
        };
        let exclusion_hash = match self.content_store.put(entity) {
            Ok(h) => h,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "store_failed",
                    &e.to_string(),
                ))
            }
        };
        let exclusion_path = self.qualify(&path);
        // The resource path may already be peer-qualified; if so, qualify()
        // would double-prefix. Detect and normalize.
        let exclusion_path = if path.starts_with(&self.qualified_prefix)
            || path.starts_with('/')
        {
            path.clone()
        } else {
            exclusion_path
        };
        self.location_index.set(&exclusion_path, exclusion_hash);

        // R7 layer 1: sweep role-derived tokens for the excluded peer.
        let revoked = self.sweep_role_derived(&context, &peer_id);

        Ok(exclude_result(&exclusion_path, &revoked))
    }

    // -------------------------------------------------------------------
    // §4.4 unexclude — remove exclusion entity (no auto-restore, per §6.4)
    // -------------------------------------------------------------------

    async fn handle_unexclude(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "ambiguous_resource",
                    "unexclude requires the exclusion path as resource",
                ))
            }
        };
        if parse_exclusion_path(&path).is_none() {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "malformed_resource",
                "expected system/role/{context}/excluded/{peer_id}",
            ));
        }
        // §6.4: removing the exclusion does NOT auto-restore role-derived
        // tokens; re-assignment is required. So this is a single tree
        // remove.
        self.location_index.remove(&path);
        Ok(unexclude_result(&path))
    }

    // -------------------------------------------------------------------
    // Token derivation + sweep helpers
    // -------------------------------------------------------------------

    /// Build, sign, persist a role-derived capability token at the pinned
    /// R4 storage path. Also writes the linkage entity (SI-5 v1.6) at
    /// `system/role/{ctx}/derived-tokens/{peer_id_hex}/{role_name}` so
    /// `unassign` and `:delegate` can locate the cap deterministically.
    /// Returns the token's content hash on success.
    ///
    /// PR-1 (PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS §2): the role-derived
    /// cap is structurally a ROOT cap (`parent: null`), structurally
    /// identical to the startup-time L0 path per EXTENSION-ROLE.md §4.5.
    /// The `parent` parameter is kept generic for the rare delegation-style
    /// caller; assign / re-derive callers pass `None`. Use-time chain
    /// validation terminates at the role-derived cap regardless of how
    /// narrow the handler grant is — required for non-dev peers.
    fn derive_and_persist_token(
        &self,
        context: &str,
        assignee_id_hex: &str,
        role_name: &str,
        grantee: Hash,
        grants: Vec<GrantEntry>,
        parent: Option<Hash>,
        expires_at: Option<u64>,
    ) -> Result<Hash, String> {
        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let token = CapabilityToken {
            grants,
            granter: Granter::Single(self.identity_hash),
            grantee,
            parent,
            created_at: now_ms,
            // v1.7 §5.3 / SI-29: caller is responsible for computing
            // MIN_DEFINED(parent.expires_at, role.ttl, caller.expires_at).
            // Without this, V7 §5.6 chain validation rejects the cap at
            // use-time even when RL2 grant-coverage passed at issue-time.
            expires_at,
            not_before: None,
            delegation_caveats: None,
        };
        let cap_entity = token.to_entity().map_err(|e| e.to_string())?;
        let cap_hash = self
            .content_store
            .put(cap_entity.clone())
            .map_err(|e| e.to_string())?;

        // Sign the cap so chain validation accepts it (V7 §5.5).
        let sig_bytes = self.keypair.sign(&cap_entity.content_hash.to_bytes());
        let sig_data = to_ecf(&Value::Map(vec![
            (text("algorithm"), text(self.keypair.key_type().label())),
            (text("signature"), Value::Bytes(sig_bytes)),
            (
                text("signer"),
                Value::Bytes(self.identity_hash.to_bytes().to_vec()),
            ),
            (
                text("target"),
                Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
            ),
        ]));
        let sig_entity =
            Entity::new(TYPE_SIGNATURE, sig_data).map_err(|e| e.to_string())?;
        let sig_hash = self
            .content_store
            .put(sig_entity)
            .map_err(|e| e.to_string())?;

        let cap_path = self.qualify(&path_role_derived_token(
            context,
            assignee_id_hex,
            &hex_segment(&cap_hash),
        ));
        self.location_index.set(&cap_path, cap_hash);
        // V7 §3.5 (v7.44, normative MUST): a role-derived cap is a
        // transportable chain root (ROLE PR-1), so its signature MUST be
        // discoverable at the invariant pointer path — that is the only
        // peer-agnostic location `collect_chain_bundle` / envelope ingest
        // can find to transport & re-verify it cross-peer. ROLE pins no
        // signature path and delegates chain verification to V7, so the
        // invariant pointer is the sole canonical location; no sibling
        // copy (no Rust production reader; matches the Go reference).
        self.location_index.set(
            &invariant_signature_path(&self.local_peer_id, &cap_hash),
            sig_hash,
        );

        // SI-5 v1.6: write the linkage entity at the sibling subtree.
        let link = RoleDerivedTokenLinkData {
            token_hash: cap_hash,
            issued_at: now_ms,
        };
        let link_entity = link.to_entity().map_err(|e| e.to_string())?;
        let link_hash = self
            .content_store
            .put(link_entity)
            .map_err(|e| e.to_string())?;
        let link_path = self.qualify(&path_role_derived_link(
            context,
            assignee_id_hex,
            role_name,
        ));
        self.location_index.set(&link_path, link_hash);

        Ok(cap_hash)
    }

    /// PR-2 (PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS §3 / SEC-2): rollback
    /// helper. After a role-derived cap is bound by `derive_and_persist_token`,
    /// a concurrent `:exclude` may have completed its sweep before the cap
    /// landed. The post-issue `is_excluded` re-check in callers detects this
    /// race; this helper undoes the binding by removing the cap, its sibling
    /// signature, and the linkage entity at their canonical paths. The
    /// content-store entries become orphans (the LocationIndex no longer
    /// resolves them), matching Go's `TreeRemove`-only rollback shape.
    /// `delete_link` is false for delegate (delegate has no linkage entity).
    fn rollback_role_derived_cap(
        &self,
        context: &str,
        peer_id_hex: &str,
        role_name: &str,
        cap_hash: Hash,
        delete_link: bool,
    ) {
        let cap_path = self.qualify(&path_role_derived_token(
            context,
            peer_id_hex,
            &hex_segment(&cap_hash),
        ));
        self.location_index.remove(&cap_path);
        // V7 §3.5 v7.44: signature lives at the invariant pointer path.
        self.location_index.remove(&invariant_signature_path(
            &self.local_peer_id,
            &cap_hash,
        ));
        if delete_link {
            let link_path =
                self.qualify(&path_role_derived_link(context, peer_id_hex, role_name));
            self.location_index.remove(&link_path);
        }
    }

    // -------------------------------------------------------------------
    // §4.2 / IA11 define — write/replace a role definition + re-derive
    // -------------------------------------------------------------------

    async fn handle_define(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "ambiguous_resource",
                    "define requires the role-definition path as resource",
                ))
            }
        };
        let parsed = match parse_role_definition_path(&path) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "malformed_resource",
                    "expected system/role/{context}/{role_name} (reserved names rejected per R10)",
                ))
            }
        };
        let ParsedRoleDefPath { context, role_name } = parsed;

        // Decode params: { grants: [grant-entry], metadata?: any }
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))
            }
        };
        let grants_value = match get_field(&map, "grants") {
            Some(v) => v,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "grants array is required",
                ))
            }
        };
        let grants = match decode_grant_array_value(grants_value) {
            Ok(g) => g,
            Err(e) => {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))
            }
        };
        let metadata = match get_field(&map, "metadata") {
            None | Some(ciborium::Value::Null) => None,
            Some(ciborium::Value::Map(m)) => Some(m.clone()),
            Some(_) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "metadata must be a CBOR map",
                ))
            }
        };

        // RL2 at definition-write time (§9.6 IA11). The grants here are
        // the *templates* with `{context}`/`{peer_id}` placeholders. To
        // check coverage soundly we resolve `{context}` (we know it) and
        // leave `{peer_id}` as a literal string — pattern matching in
        // `is_attenuated` accepts literal segments, so any caller cap
        // covering the resolved-with-{peer_id} path covers any concrete
        // assignee. This is the same property the spec relies on: a
        // template grant covers the union of resolved instances iff the
        // caller cap covers the template itself.
        let template_resolved: Vec<GrantEntry> = grants
            .iter()
            .map(|g| resolve_grant_templates(g, &context, "{peer_id}"))
            .collect();
        let caller_cap = match &ctx.caller_capability {
            Some(c) => c,
            None => {
                return Ok(error(
                    STATUS_FORBIDDEN,
                    "missing_caller_capability",
                    "RL2: caller_capability required for define",
                ))
            }
        };
        // v1.7 §5.3: define-time RL2 only has the caller bound to lean
        // on (no parent cap, no role TTL — the role definition is being
        // written *now*, and TTL would come from this metadata). Compute
        // the bound from caller alone for the hypothetical so RL2 sees
        // the same shape.
        let define_expires_at = caller_cap.expires_at;
        let hypothetical = build_hypothetical_token(
            template_resolved,
            caller_cap,
            self.identity_hash,
            define_expires_at,
        );
        if !is_attenuated(&hypothetical, caller_cap, &self.local_peer_id) {
            return Ok(error(
                STATUS_FORBIDDEN,
                "assigner_authority_insufficient",
                &format!(
                    "RL2: caller capability does not cover the proposed grant set for {}",
                    role_name
                ),
            ));
        }

        // Persist the role-definition entity.
        let role_def = RoleData {
            name: role_name.clone(),
            grants,
            metadata,
        };
        let entity = match role_def.to_entity() {
            Ok(e) => e,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "encode_failed",
                    &e.to_string(),
                ))
            }
        };
        let role_hash = match self.content_store.put(entity) {
            Ok(h) => h,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "store_failed",
                    &e.to_string(),
                ))
            }
        };
        let role_def_path = self.qualify(&path_role_definition(&context, &role_name));
        self.location_index.set(&role_def_path, role_hash);

        // Re-derive cascade per §5.5 / IA9 (issue-first ordering). The
        // caller's cap is passed for the per-assignee RL2 re-check
        // (SI-15 skip-and-continue).
        let re_derived = self.re_derive_role_assignees(
            &context,
            &role_name,
            ctx.caller_capability.as_ref(),
        )?;

        Ok(define_result(&role_def_path, re_derived))
    }

    // -------------------------------------------------------------------
    // §4.2 / R5 re-derive — re-issue tokens for all assignees of a role
    // -------------------------------------------------------------------

    async fn handle_re_derive(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "ambiguous_resource",
                    "re-derive requires the role-definition path as resource",
                ))
            }
        };
        let parsed = match parse_role_definition_path(&path) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "malformed_resource",
                    "expected system/role/{context}/{role_name}",
                ))
            }
        };
        let ParsedRoleDefPath { context, role_name } = parsed;

        // Validate params.role matches path (defensive symmetry with assign).
        if let Ok(map) = decode_map(&ctx.params.data) {
            if let Ok(req_role) = field_text(&map, "role") {
                if req_role != role_name {
                    return Ok(error(
                        STATUS_BAD_REQUEST,
                        "role_path_mismatch",
                        "params.role must match the resource path's role segment",
                    ));
                }
            }
        }

        // 404 if the role-definition path is unbound — necessary so the
        // op surfaces the missing-role case before walking assignments.
        let role_def_path = self.qualify(&path_role_definition(&context, &role_name));
        if self.location_index.get(&role_def_path).is_none() {
            return Ok(error(
                STATUS_NOT_FOUND,
                "role_not_found",
                "no role definition at the given resource path",
            ));
        }

        // Per SI-15 (v1.7 cross-impl handoff): NO outer cascade-wide RL2
        // abort. Earlier impls of this handler did a template-time check
        // here that returned 403 if the caller's authority didn't cover
        // the template grants resolved with `{peer_id}` literal — but
        // that aborts the whole cascade and leaves earlier ordered-write
        // pairs half-applied (security regression). Per-assignee RL2
        // happens inside `re_derive_role_assignees` and routes failures
        // into `summary.skipped_grantees`. Caller-capability presence is
        // still required so the per-assignee check has something to
        // attenuate against.
        if ctx.caller_capability.is_none() {
            return Ok(error(
                STATUS_FORBIDDEN,
                "missing_caller_capability",
                "RL2: caller_capability required for re-derive",
            ));
        }

        let summary = self.re_derive_role_assignees(
            &context,
            &role_name,
            ctx.caller_capability.as_ref(),
        )?;
        Ok(re_derive_result(summary))
    }

    // -------------------------------------------------------------------
    // §4.2 / §5.6 / IA22 delegate — member-to-member delegation
    // -------------------------------------------------------------------

    async fn handle_delegate(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))
            }
        };

        // SI-21 v1.6: no `delegator` field on the request. Caller is
        // implicit from ctx.execute.data.author (V7 envelope-level).
        // SI-19 v1.6: `:delegate` MUST run on the delegator's own peer.
        // The delegator IS the local peer's identity; `ctx.author` MUST
        // equal `self.identity_hash`. 400 (precondition error), not 403.
        let delegator = match ctx.author {
            Some(h) => h,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "delegator_must_be_local_peer",
                    "missing envelope author (SI-19: delegate is local-only)",
                ))
            }
        };
        if delegator != self.identity_hash {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "delegator_must_be_local_peer",
                "SI-19: :delegate MUST be invoked on the delegator's own runtime peer",
            ));
        }

        // SI-4 v1.6: context/role are primitive/string.
        let delegate_hash = match field_hash(&map, "delegate") {
            Ok(h) => h,
            Err(e) => {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))
            }
        };
        // SEC-18 / V7 v7.39 PR-3: reject zero-hash delegate. Mirrors the
        // assign-time check (Go reference). The minted delegation
        // cap would fail chain-walk under `unresolvable_grantee` anyway.
        if delegate_hash.is_zero() {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "invalid_delegate_request",
                "delegate hash MUST NOT be a zero hash (SEC-18)",
            ));
        }
        let context = match field_text(&map, "context") {
            Ok(s) => s,
            Err(e) => {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))
            }
        };
        let role_name = match field_text(&map, "role") {
            Ok(s) => s,
            Err(e) => {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))
            }
        };
        let scope_value = match get_field(&map, "scope") {
            Some(v) => v,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "invalid_params",
                    "scope is required",
                ))
            }
        };
        let scope = match decode_grant_array_value(scope_value) {
            Ok(g) => g,
            Err(e) => {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))
            }
        };
        let expires_at = match field_u64_opt(&map, "expires_at") {
            Ok(v) => v,
            Err(e) => {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string()))
            }
        };

        // SI-20 v1.6: scope MUST be literal — no `{context}` or
        // `{peer_id}` substrings. Reject 400 `scope_must_be_literal`.
        if scope_contains_template(&scope) {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "scope_must_be_literal",
                "SI-20: delegation scope must be literal — no template variables",
            ));
        }

        // SI-1 v1.6: delegate path-segment is hex of identity hash.
        let delegate_segment = peer_segment_from_hash(&delegate_hash);
        let delegator_segment = peer_segment_from_hash(&delegator);

        // R7 layer 2: an excluded delegate cannot receive new caps.
        if is_excluded(
            &self.location_index,
            &self.qualified_prefix,
            &context,
            &delegate_segment,
        ) {
            return Ok(error(
                STATUS_FORBIDDEN,
                "delegate_excluded",
                "Cannot delegate role-authority to a peer in the context's exclusion subtree",
            ));
        }

        // §5.6 step 2: verify B holds the named role.
        let assignment_path =
            self.qualify(&path_role_assignment(&context, &delegator_segment, &role_name));
        if self.location_index.get(&assignment_path).is_none() {
            return Ok(error(
                STATUS_FORBIDDEN,
                "delegator_does_not_hold_role",
                "delegator must hold the named role in this context (§5.6 step 2)",
            ));
        }

        // SI-22 v1.6: parent selection via the linkage entity.
        let link_path =
            self.qualify(&path_role_derived_link(&context, &delegator_segment, &role_name));
        let link_hash = match self.location_index.get(&link_path) {
            Some(h) => h,
            None => {
                return Ok(error(
                    STATUS_FORBIDDEN,
                    "no_parent_cap",
                    "no derived-token linkage entity for delegator's role assignment",
                ))
            }
        };
        let link_entity = match self.content_store.get(&link_hash) {
            Some(e) => e,
            None => {
                return Ok(error(
                    STATUS_FORBIDDEN,
                    "no_parent_cap",
                    "linkage entity bound but missing in content store",
                ))
            }
        };
        let link = match RoleDerivedTokenLinkData::from_entity(&link_entity) {
            Ok(l) => l,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "linkage_decode_failed",
                    &e.to_string(),
                ))
            }
        };
        let parent_token_hash = link.token_hash;
        let parent_entity = match self.content_store.get(&parent_token_hash) {
            Some(e) => e,
            None => {
                return Ok(error(
                    STATUS_FORBIDDEN,
                    "no_parent_cap",
                    "linkage references token hash that is missing from content store",
                ))
            }
        };
        let parent_token = match CapabilityToken::from_entity(&parent_entity) {
            Ok(t) => t,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "parent_decode_failed",
                    &e.to_string(),
                ))
            }
        };

        // RL2 against delegator's authority (NOT the operational key's
        // per IA22). Scope is literal (SI-20), so we compare it as-is.
        // v1.7 §5.3: compute MIN_DEFINED expires_at first so the
        // hypothetical and the persisted cap share shape.
        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let delegation_expires_at = effective_expires_at(
            parent_token.expires_at,
            None, // no role TTL — delegation isn't role-derived from a fresh role def
            expires_at, // request-supplied cap (acts as caller's cap bound here)
            now_ms,
        );
        let hypothetical = build_hypothetical_token(
            scope.clone(),
            &parent_token,
            self.identity_hash,
            delegation_expires_at,
        );
        if !is_attenuated(&hypothetical, &parent_token, &self.local_peer_id) {
            return Ok(error(
                STATUS_FORBIDDEN,
                "scope_exceeds_delegator_authority",
                "delegated scope is not an attenuation of the delegator's role-derived cap",
            ));
        }

        // Persist + sign the delegation cap. SI-19 makes the locality
        // invariant: handler holds the delegator's keypair, so signing
        // happens here (no out-of-band step).
        let delegation_token = CapabilityToken {
            grants: scope,
            granter: Granter::Single(delegator),
            grantee: delegate_hash,
            parent: Some(parent_token_hash),
            created_at: now_ms,
            expires_at: delegation_expires_at,
            not_before: None,
            delegation_caveats: None,
        };
        let cap_entity = match delegation_token.to_entity() {
            Ok(e) => e,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "encode_failed",
                    &e.to_string(),
                ))
            }
        };
        let cap_hash = match self.content_store.put(cap_entity.clone()) {
            Ok(h) => h,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "store_failed",
                    &e.to_string(),
                ))
            }
        };
        let sig_bytes = self.keypair.sign(&cap_entity.content_hash.to_bytes());
        let sig_data = to_ecf(&Value::Map(vec![
            (text("algorithm"), text(self.keypair.key_type().label())),
            (text("signature"), Value::Bytes(sig_bytes)),
            (
                text("signer"),
                Value::Bytes(self.identity_hash.to_bytes().to_vec()),
            ),
            (
                text("target"),
                Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
            ),
        ]));
        let sig_entity = match Entity::new(TYPE_SIGNATURE, sig_data) {
            Ok(e) => e,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "sig_encode_failed",
                    &e.to_string(),
                ))
            }
        };
        let sig_hash = match self.content_store.put(sig_entity) {
            Ok(h) => h,
            Err(e) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "store_failed",
                    &e.to_string(),
                ))
            }
        };

        let cap_path = self.qualify(&path_role_derived_token(
            &context,
            &delegate_segment,
            &hex_segment(&cap_hash),
        ));
        self.location_index.set(&cap_path, cap_hash);
        // V7 §3.5 (v7.44 MUST): delegated role-derived caps are
        // transportable chain links — signature at the invariant pointer
        // path (sole canonical location; no sibling — matches Go).
        self.location_index.set(
            &invariant_signature_path(&self.local_peer_id, &cap_hash),
            sig_hash,
        );

        // PR-2 (SEC-2 atomicity, §6.6): post-issue exclusion re-check.
        // A concurrent `:exclude` against the delegate may have landed
        // between the pre-check above and the cap bind. Roll back if so.
        // Delegate has no linkage entity (delegate is the recipient, not
        // an assignee — linkage entities are only written by `:assign` and
        // re-derive cascades), so `delete_link: false`.
        if is_excluded(
            &self.location_index,
            &self.qualified_prefix,
            &context,
            &delegate_segment,
        ) {
            self.rollback_role_derived_cap(&context, &delegate_segment, &role_name, cap_hash, false);
            return Ok(error(
                STATUS_FORBIDDEN,
                "delegate_excluded",
                "exclusion landed during :delegate — rolled back per §6.6 atomicity",
            ));
        }

        Ok(delegate_result(cap_hash))
    }

    /// Re-derive cascade: walk every assignee of `(context, role_name)`,
    /// issue T_new BEFORE revoking T_old (IA9 issue-first default), and
    /// return the per-assignee summary. Excluded peers are skipped (R7
    /// layer 2). Per SI-15 (skip-and-continue), an assignee whose
    /// per-peer RL2 check fails mid-cascade is recorded in
    /// `skipped_grantees` and the cascade continues; that assignee
    /// keeps T_old.
    fn re_derive_role_assignees(
        &self,
        context: &str,
        role_name: &str,
        caller_cap: Option<&CapabilityToken>,
    ) -> Result<ReDeriveSummary, HandlerError> {
        // Read current role definition for grant templates.
        let role_def_path = self.qualify(&path_role_definition(context, role_name));
        let role_hash = match self.location_index.get(&role_def_path) {
            Some(h) => h,
            None => return Ok(ReDeriveSummary::default()),
        };
        let role_entity = match self.content_store.get(&role_hash) {
            Some(e) => e,
            None => return Ok(ReDeriveSummary::default()),
        };
        let role_def = match RoleData::from_entity(&role_entity) {
            Ok(r) => r,
            Err(_) => return Ok(ReDeriveSummary::default()),
        };

        let assignment_prefix = self.qualify(&prefix_role_assignment(context));
        let entries = self.location_index.list(&assignment_prefix);

        let mut summary = ReDeriveSummary::default();
        // v1.7 §5.3: handler grant's expires_at feeds the MIN_DEFINED bound
        // for the issued cap (and the RL2 hypothetical). PR-1: the handler-
        // grant hash is NOT used as the issued cap's `parent` — role-derived
        // caps are root caps. We still load the handler-grant token here to
        // read its `expires_at`.
        let handler_grant_hash = self.location_index.get(&self.qualified_pattern.replace(
            "/system/role",
            "/system/capability/grants/system/role",
        ));
        let parent_expires = handler_grant_hash
            .and_then(|h| self.content_store.get(&h))
            .and_then(|e| CapabilityToken::from_entity(&e).ok())
            .and_then(|t| t.expires_at);
        let role_ttl = role_metadata_ttl(&role_def.metadata);
        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        for entry in entries {
            // entry.path = `/{pid}/system/role/{context}/assignment/{peer_id_hex}/{role_name}`
            let parsed = match parse_assignment_path(&entry.path) {
                Some(p) => p,
                None => continue,
            };
            // Filter by trailing role segment (multi-role per peer).
            let entry_role = match parsed.role_name.as_deref() {
                Some(r) => r,
                None => continue,
            };
            if entry_role != role_name {
                continue;
            }
            let assignee_hex = parsed.peer_id.clone();

            // Layer-2 exclusion: skip excluded assignees (R7 L2).
            if is_excluded(
                &self.location_index,
                &self.qualified_prefix,
                context,
                &assignee_hex,
            ) {
                summary.skipped_excluded += 1;
                continue;
            }

            // SI-1 / SI-8: assignee path-segment IS hex of identity hash.
            let grantee_hash = match hash_from_peer_segment(&assignee_hex) {
                Some(h) => h,
                None => continue, // malformed segment — skip silently
            };
            // SEC-18: a stale assignment whose path encodes the zero-hash
            // assignee MUST NOT re-mint a cap. Skip silently — same shape
            // as the malformed-segment branch — because the chain-walk
            // would reject any minted cap at use time anyway.
            if grantee_hash.is_zero() {
                continue;
            }

            let derived_grants: Vec<GrantEntry> = role_def
                .grants
                .iter()
                .map(|g| resolve_grant_templates(g, context, &assignee_hex))
                .collect();

            // v1.7 §5.3: per-assignee MIN_DEFINED expires_at, computed
            // BEFORE the RL2 check so the hypothetical and persisted cap
            // share shape.
            let cap_expires_at = effective_expires_at(
                parent_expires,
                role_ttl,
                caller_cap.and_then(|c| c.expires_at),
                now_ms,
            );

            // SI-15 v1.6: per-assignee RL2 check (skip-and-continue).
            // The caller's authority must cover the resolved-with-this-
            // assignee grants. Differs from `define`'s template-time
            // check, which checks against `{peer_id}` literal — that
            // covers the union; here we re-check per concrete assignee
            // because peer-specific templates may push some assignees
            // outside the caller's authority.
            if let Some(cap) = caller_cap {
                let hyp = build_hypothetical_token(
                    derived_grants.clone(),
                    cap,
                    self.identity_hash,
                    cap_expires_at,
                );
                if !is_attenuated(&hyp, cap, &self.local_peer_id) {
                    summary.skipped_grantees.push(grantee_hash);
                    continue;
                }
            }

            // IA9 issue-first: persist T_new before revoking T_old.
            // PR-1: parent: None — role-derived caps are root caps.
            let new_token_hash = match self.derive_and_persist_token(
                context,
                &assignee_hex,
                role_name,
                grantee_hash,
                derived_grants,
                None,
                cap_expires_at,
            ) {
                Ok(h) => h,
                Err(_) => {
                    // Issue failed; per IA9 safety, leave T_old in place.
                    continue;
                }
            };

            // PR-2 (SEC-2 atomicity, §6.6): post-issue exclusion re-check.
            // A concurrent `:exclude` may have landed the exclusion entity
            // and run its layer-1 sweep against this peer's role-derived
            // subtree between the per-assignee pre-check and the cap bind.
            // If excluded, roll back the new cap + sig + linkage and route
            // the grantee into `skipped_grantees` (consistent with SI-15
            // skip-and-continue). T_old is left in place because we never
            // got to the sweep step.
            if is_excluded(
                &self.location_index,
                &self.qualified_prefix,
                context,
                &assignee_hex,
            ) {
                self.rollback_role_derived_cap(
                    context,
                    &assignee_hex,
                    role_name,
                    new_token_hash,
                    true,
                );
                summary.skipped_grantees.push(grantee_hash);
                continue;
            }

            summary.new_token_hashes.push(new_token_hash);

            // Now sweep prior tokens (everything at the role-derived path
            // for this peer that ISN'T the new token). Signatures no longer
            // live under this prefix (V7 §3.5 v7.44 — invariant pointer
            // path), so each swept cap's sig is unbound there explicitly.
            // The linkage entity for this (peer, role) was overwritten by
            // `derive_and_persist_token` — cascade is correct.
            let derived_prefix =
                self.qualify(&prefix_role_derived_peer(context, &assignee_hex));
            let new_cap_path = self.qualify(&path_role_derived_token(
                context,
                &assignee_hex,
                &hex_segment(&new_token_hash),
            ));
            for prior in self.location_index.list(&derived_prefix) {
                if prior.path == new_cap_path {
                    continue;
                }
                let is_cap = self
                    .content_store
                    .get(&prior.hash)
                    .map(|e| e.entity_type == "system/capability/token")
                    .unwrap_or(false);
                if let Some(h) = self.location_index.remove(&prior.path) {
                    if is_cap {
                        summary.revoked_token_hashes.push(h);
                        self.location_index.remove(&invariant_signature_path(
                            &self.local_peer_id,
                            &h,
                        ));
                    }
                }
            }
            summary.re_derived_count += 1;
        }

        Ok(summary)
    }

    /// Layer-1 sweep: delete every role-derived token for (context,
    /// peer_id). Returns the hashes of the swept tokens for the result
    /// payload.
    fn sweep_role_derived(&self, context: &str, peer_id: &str) -> Vec<Hash> {
        let prefix = self.qualify(&prefix_role_derived_peer(context, peer_id));
        let entries = self.location_index.list(&prefix);
        let mut revoked = Vec::new();
        for entry in entries {
            // Only count caps in the returned revoked list. Signatures live
            // at the invariant pointer path (V7 §3.5 v7.44), not under this
            // prefix, so each swept cap's sig is unbound there explicitly
            // (orphaned sigs are harmless — chain validation gates on the
            // cap path — but we clean up for tree hygiene, matching Go).
            let is_cap = self
                .content_store
                .get(&entry.hash)
                .map(|e| e.entity_type == "system/capability/token")
                .unwrap_or(false);
            if let Some(h) = self.location_index.remove(&entry.path) {
                if is_cap {
                    revoked.push(h);
                    self.location_index.remove(&invariant_signature_path(
                        &self.local_peer_id,
                        &h,
                    ));
                }
            }
        }
        revoked
    }
}

// ---------------------------------------------------------------------------
// RL2 hypothetical-token construction
// ---------------------------------------------------------------------------

/// Build a synthetic token holding the role's derived grants, used as the
/// "child" in `is_attenuated(child, parent=caller_cap)`. The hypothetical's
/// `expires_at` MUST be the same MIN_DEFINED value the issued cap will get
/// (per v1.7 §5.3 + §4.3 step 5) — otherwise RL2 passes at issue-time
/// against the wrong shape and V7 §5.6 chain validation rejects at use-time
/// ("RL2 OK at issue, chain-invalid at use").
fn build_hypothetical_token(
    grants: Vec<GrantEntry>,
    caller_cap: &CapabilityToken,
    _identity_hash: Hash,
    expires_at: Option<u64>,
) -> CapabilityToken {
    CapabilityToken {
        grants,
        granter: caller_cap.granter.clone(),
        grantee: caller_cap.grantee,
        parent: None,
        created_at: caller_cap.created_at,
        expires_at,
        not_before: None,
        delegation_caveats: None,
    }
}

/// v1.7 §5.3 / SI-29: take the minimum of the defined sources, ignoring
/// `None`. If all sources are `None`, return `None` (vacuous bound —
/// child MAY have any expiry per V7 §5.6 line 643 when parent has none).
fn min_defined(values: &[Option<u64>]) -> Option<u64> {
    values
        .iter()
        .filter_map(|v| *v)
        .min()
}

/// v1.7 §5.3 item 4: the role's optional `metadata.ttl` (milliseconds).
/// Returns the TTL value in ms; the absolute expires_at is `now + ttl`.
pub(crate) fn role_metadata_ttl(
    metadata: &Option<Vec<(ciborium::Value, ciborium::Value)>>,
) -> Option<u64> {
    let map = metadata.as_ref()?;
    for (k, v) in map {
        if k.as_text() == Some("ttl") {
            if let Some(i) = v.as_integer() {
                let n: i128 = i.into();
                if n >= 0 {
                    return Some(n as u64);
                }
            }
        }
    }
    None
}

/// Compute the issued cap's `expires_at` per v1.7 §5.3 + §4.3 step 5:
/// `MIN_DEFINED(parent.expires_at, now + role.ttl, caller.expires_at)`.
/// All three sources are optional; missing sources are skipped, not
/// treated as zero.
fn effective_expires_at(
    parent_expires: Option<u64>,
    role_ttl_ms: Option<u64>,
    caller_expires: Option<u64>,
    now_ms: u64,
) -> Option<u64> {
    let role_expires = role_ttl_ms.map(|ttl| now_ms.saturating_add(ttl));
    min_defined(&[parent_expires, role_expires, caller_expires])
}

/// SI-20 v1.6: detect template variables in any path-shaped field of a
/// grant entry. Used to reject delegate `scope` parameters that contain
/// `{context}` or `{peer_id}` substrings (those substitutions only apply
/// to role-definition grants, never to delegation scopes).
fn scope_contains_template(scope: &[GrantEntry]) -> bool {
    fn contains_template(s: &str) -> bool {
        s.contains("{context}") || s.contains("{peer_id}")
    }
    for g in scope {
        if g.handlers.include.iter().any(|s| contains_template(s)) {
            return true;
        }
        if g.handlers.exclude.iter().any(|s| contains_template(s)) {
            return true;
        }
        if g.resources.include.iter().any(|s| contains_template(s)) {
            return true;
        }
        if g.resources.exclude.iter().any(|s| contains_template(s)) {
            return true;
        }
        if g.operations.include.iter().any(|s| contains_template(s)) {
            return true;
        }
        if g.operations.exclude.iter().any(|s| contains_template(s)) {
            return true;
        }
        if let Some(p) = &g.peers {
            if p.include.iter().any(|s| contains_template(s)) {
                return true;
            }
            if p.exclude.iter().any(|s| contains_template(s)) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Result + error helpers
// ---------------------------------------------------------------------------

fn error(status: u32, code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(status, error_entity(code, message))
}

fn assign_result(path: &str, derived_tokens: &[Hash]) -> HandlerResult {
    let mut fields: Vec<(Value, Value)> =
        vec![(text("assignment_path"), text(path))];
    if !derived_tokens.is_empty() {
        let arr: Vec<Value> = derived_tokens
            .iter()
            .map(|h| Value::Bytes(h.to_bytes().to_vec()))
            .collect();
        fields.push((text("derived_tokens"), Value::Array(arr)));
    }
    let result = Entity::new(TYPE_ROLE_ASSIGN_RESULT, to_ecf(&Value::Map(fields))).unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

fn define_result(path: &str, summary: ReDeriveSummary) -> HandlerResult {
    let mut fields: Vec<(Value, Value)> = vec![(text("role_path"), text(path))];
    if summary.re_derived_count > 0 {
        fields.push((
            text("re_derived_count"),
            entity_ecf::integer(summary.re_derived_count as i64),
        ));
    }
    let result = Entity::new(
        entity_types::TYPE_ROLE_DEFINE_RESULT,
        to_ecf(&Value::Map(fields)),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

fn unassign_result(path: &str, revoked: &[Hash]) -> HandlerResult {
    let mut fields: Vec<(Value, Value)> =
        vec![(text("assignment_path"), text(path))];
    if !revoked.is_empty() {
        let arr: Vec<Value> = revoked
            .iter()
            .map(|h| Value::Bytes(h.to_bytes().to_vec()))
            .collect();
        fields.push((text("revoked_token_hashes"), Value::Array(arr)));
    }
    let result = Entity::new(
        entity_types::TYPE_ROLE_UNASSIGN_RESULT,
        to_ecf(&Value::Map(fields)),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

fn unexclude_result(path: &str) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_ROLE_UNEXCLUDE_RESULT,
        to_ecf(&Value::Map(vec![(text("exclusion_path"), text(path))])),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

fn delegate_result(token_hash: Hash) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_ROLE_DELEGATE_RESULT,
        to_ecf(&Value::Map(vec![(
            text("delegation_token_hash"),
            Value::Bytes(token_hash.to_bytes().to_vec()),
        )])),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

fn re_derive_result(summary: ReDeriveSummary) -> HandlerResult {
    let mut fields: Vec<(Value, Value)> = vec![(
        text("re_derived_count"),
        entity_ecf::integer(summary.re_derived_count as i64),
    )];
    if !summary.revoked_token_hashes.is_empty() {
        let arr: Vec<Value> = summary
            .revoked_token_hashes
            .iter()
            .map(|h| Value::Bytes(h.to_bytes().to_vec()))
            .collect();
        fields.push((text("revoked_token_hashes"), Value::Array(arr)));
    }
    if !summary.new_token_hashes.is_empty() {
        let arr: Vec<Value> = summary
            .new_token_hashes
            .iter()
            .map(|h| Value::Bytes(h.to_bytes().to_vec()))
            .collect();
        fields.push((text("new_token_hashes"), Value::Array(arr)));
    }
    if !summary.skipped_grantees.is_empty() {
        let arr: Vec<Value> = summary
            .skipped_grantees
            .iter()
            .map(|h| Value::Bytes(h.to_bytes().to_vec()))
            .collect();
        fields.push((text("skipped_grantees"), Value::Array(arr)));
    }
    let result = Entity::new(
        entity_types::TYPE_ROLE_RE_DERIVE_RESULT,
        to_ecf(&Value::Map(fields)),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

/// Aggregated outcome of `re_derive_role_assignees`. Returned to both the
/// `define` cascade (re_derived_count surfaces as `define-result.re_derived_count`)
/// and the explicit `re-derive` op.
///
/// SI-15 v1.6: `skipped_grantees` records assignees whose per-peer RL2
/// check failed mid-cascade — they retain T_old. Surfaced through
/// `re-derive-result.skipped_grantees` as `array_of system/hash`.
#[derive(Default)]
struct ReDeriveSummary {
    re_derived_count: u64,
    skipped_excluded: u64,
    revoked_token_hashes: Vec<Hash>,
    new_token_hashes: Vec<Hash>,
    skipped_grantees: Vec<Hash>,
}

fn exclude_result(path: &str, revoked: &[Hash]) -> HandlerResult {
    let mut fields: Vec<(Value, Value)> = vec![(text("exclusion_path"), text(path))];
    if !revoked.is_empty() {
        let arr: Vec<Value> = revoked
            .iter()
            .map(|h| Value::Bytes(h.to_bytes().to_vec()))
            .collect();
        fields.push((text("revoked_token_hashes"), Value::Array(arr)));
    }
    let result =
        Entity::new(TYPE_ROLE_EXCLUDE_RESULT, to_ecf(&Value::Map(fields))).unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

// Suppress unused-warning for TYPE_ROLE / IdScope / PathScope at the top
// when only some are used; Phase 4 (define) will use them.
#[allow(dead_code)]
fn _phase4_uses() {
    let _ = TYPE_ROLE;
    let _ = IdScope::all();
    let _ = PathScope::all();
}
