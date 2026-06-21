//! Initial-grant policy resolver for the connect handler
//! (EXTENSION-ROLE §4.7, ENTITY-CORE-PROTOCOL-V7 §7.2).
//!
//! At AUTHENTICATE the connect handler asks a `GrantResolver` what grants
//! to put on the inbound connection cap. With this module wired, the
//! resolver dispatches on the `system/role/initial-grant-policy` entity:
//!
//! - `anonymous-deny` (default) — return `None` (fall through to static
//!   fallback `default_connection_grants`).
//! - `anonymous-allow` — return `default_role`'s grants for everyone.
//! - `recognize-on-attestation` — return `default_role`'s grants only
//!   when the connecting peer's `system/peer` content hash terminates a
//!   live agent identity-cert chain at the `peer-config.trusts_quorum`
//!   anchor; on non-recognition, fall back per `identity_required`
//!   (true → `None` / deny, false → role grants / allow).
//!
//! Layer-2 exclusion (§6.1) fires before mode dispatch: an excluded
//! peer in `default_context` always gets `None` regardless of mode.

use std::collections::HashMap;
use std::sync::Arc;

use entity_attestation::{
    find_attestations_targeting, is_attestation_live, AttestationCtx, AttestationData,
    AttestationIndex,
};
use entity_capability::GrantEntry;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::data::{
    RoleData, RoleInitialGrantPolicyData, MODE_ANONYMOUS_ALLOW, MODE_ANONYMOUS_DENY,
    MODE_RECOGNIZE_ON_ATTESTATION,
};
use crate::helpers::is_excluded;
use crate::paths::{
    path_role_definition, peer_segment_from_hash, PATH_INITIAL_GRANT_POLICY,
};

/// Spec-pinned identity-cert kind/function strings (EXTENSION-IDENTITY
/// §3.3 / §4.2). Hardcoded here so the role crate doesn't take a dep on
/// the identity crate just for these constants — they're stable.
const KIND_IDENTITY_CERT: &str = "identity-cert";
const FUNCTION_AGENT: &str = "agent";
const FUNCTION_CONTROLLER: &str = "controller";

/// Default chain-walk depth bound (matches the attestation primitive's
/// `DEFAULT_MAX_DEPTH = 32`; HANDOFF-RECOGNIZE-ON-ATTESTATION §10.3).
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 32;

/// Read `properties.function` from an attestation. Local helper so this
/// module doesn't depend on `entity-identity`.
fn read_function(att: &AttestationData) -> Option<&str> {
    att.properties
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("function") { v.as_text() } else { None })
}

/// Read `peer-config.trusts_quorum` from the local tree. Returns `None`
/// when peer-config is unbound or decode fails — recognition is
/// impossible in that case.
fn read_trusted_quorum(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    local_peer_id: &str,
) -> Option<Hash> {
    let path = format!("/{}/system/identity/peer-config", local_peer_id);
    let pc_hash = location_index.get(&path)?;
    let pc_entity = content_store.get(&pc_hash)?;
    let value: ciborium::Value = ciborium::from_reader(pc_entity.data.as_slice()).ok()?;
    let map = value.as_map()?;
    let bytes = map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("trusts_quorum") {
            v.as_bytes()
        } else {
            None
        }
    })?;
    Hash::from_bytes(bytes).ok()
}

/// Read the policy entity. Defaults to `anonymous-deny` when absent or
/// when decode fails (HANDOFF §3 / §6 fall-closed default).
fn read_policy(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    local_peer_id: &str,
) -> RoleInitialGrantPolicyData {
    let path = format!("/{}/{}", local_peer_id, PATH_INITIAL_GRANT_POLICY);
    let Some(hash) = location_index.get(&path) else {
        return RoleInitialGrantPolicyData::default();
    };
    let Some(entity) = content_store.get(&hash) else {
        return RoleInitialGrantPolicyData::default();
    };
    RoleInitialGrantPolicyData::from_entity(&entity).unwrap_or_default()
}

/// Read a role definition's grant list. Returns `None` when the
/// role-definition entity is unbound or unparseable (fail-closed —
/// don't issue a phantom cap with empty grants per HANDOFF §6).
fn read_role_def_grants(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    local_peer_id: &str,
    context: &str,
    role_name: &str,
) -> Option<Vec<GrantEntry>> {
    let path = format!(
        "/{}/{}",
        local_peer_id,
        path_role_definition(context, role_name)
    );
    let hash = location_index.get(&path)?;
    let entity = content_store.get(&hash)?;
    let role = RoleData::from_entity(&entity).ok()?;
    Some(role.grants)
}

/// `recognize_identity_cert` per HANDOFF §5: walk the connecting peer's
/// agent identity-cert chain to a controller cert anchored at
/// `trusted_quorum`. Returns `true` iff a live chain exists within
/// `max_depth`.
///
/// Subtlety (HANDOFF §5): an agent-cert's `attesting` field points to
/// the controller's `system/peer` content hash, NOT the controller cert
/// hash. The walk is "find certs targeting this peer-hash" recursively.
pub fn recognize_identity_cert(
    attestation_index: &AttestationIndex,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    connecting_peer_hash: &Hash,
    trusted_quorum: &Hash,
    max_depth: usize,
    as_of: Option<u64>,
) -> bool {
    let included: HashMap<Hash, entity_entity::Entity> = HashMap::new();
    let ctx = AttestationCtx {
        index: attestation_index,
        content_store,
        location_index,
        included: &included,
    };
    // Step 2: find live agent identity-certs targeting the connecting peer.
    let agent_certs = find_attestations_targeting(
        connecting_peer_hash,
        |a| a.kind() == Some(KIND_IDENTITY_CERT) && read_function(a) == Some(FUNCTION_AGENT),
        &ctx,
    );
    for (agent_hash, agent) in agent_certs {
        if !is_attestation_live(&agent_hash, &agent, &ctx, as_of) {
            continue;
        }
        // Walk to trusted controller from agent.attesting (controller's peer hash).
        if walk_to_trusted_controller(&ctx, &agent.attesting, trusted_quorum, max_depth, as_of) {
            return true;
        }
    }
    false
}

/// Walk from `candidate_peer_hash` up the controller chain looking for
/// a cert anchored at `trusted_quorum`. Sub-controllers recurse via the
/// parent controller's peer hash.
fn walk_to_trusted_controller(
    ctx: &AttestationCtx,
    candidate_peer_hash: &Hash,
    trusted_quorum: &Hash,
    depth: usize,
    as_of: Option<u64>,
) -> bool {
    if depth == 0 {
        return false;
    }
    let ctrl_certs = find_attestations_targeting(
        candidate_peer_hash,
        |a| a.kind() == Some(KIND_IDENTITY_CERT) && read_function(a) == Some(FUNCTION_CONTROLLER),
        ctx,
    );
    for (cert_hash, ctrl) in ctrl_certs {
        if !is_attestation_live(&cert_hash, &ctrl, ctx, as_of) {
            continue;
        }
        if &ctrl.attesting == trusted_quorum {
            return true;
        }
        // Sub-controller: recurse via parent controller's peer hash.
        if walk_to_trusted_controller(
            ctx,
            &ctrl.attesting,
            trusted_quorum,
            depth - 1,
            as_of,
        ) {
            return true;
        }
    }
    false
}

/// Dependencies bag for `PolicyGrantResolver`.
#[derive(Clone)]
pub struct PolicyResolverDeps {
    pub content_store: Arc<dyn ContentStore>,
    pub location_index: Arc<dyn LocationIndex>,
    pub attestation_index: Arc<AttestationIndex>,
    pub local_peer_id: String,
}

/// Build the resolver function for `Peer::set_grant_resolver`. The
/// closure captures `deps` and dispatches per HANDOFF §6.
///
/// Contract: returns `Some(grants)` when the resolver decides to issue
/// connection grants, `None` to fall through to the connect handler's
/// static fallback.
#[allow(clippy::type_complexity)]
pub fn build_policy_resolver(
    deps: PolicyResolverDeps,
) -> Arc<dyn Fn(&entity_crypto::PeerId, &Hash) -> Option<Vec<GrantEntry>> + Send + Sync> {
    Arc::new(move |_peer_id, identity_hash| {
        resolve_grants(&deps, identity_hash)
    })
}

/// Pure dispatch entry point — separated for unit testing without
/// constructing a `PeerId`.
pub fn resolve_grants(
    deps: &PolicyResolverDeps,
    connecting_peer_hash: &Hash,
) -> Option<Vec<GrantEntry>> {
    let policy = read_policy(
        &deps.content_store,
        &deps.location_index,
        &deps.local_peer_id,
    );

    // Layer-2 exclusion fires before mode dispatch (§6.1). When a
    // default_context is configured AND the connecting peer is excluded
    // there, return None regardless of mode.
    if let Some(ctx) = policy.default_context.as_deref() {
        let qualified_prefix = format!("/{}/", deps.local_peer_id);
        let peer_seg = peer_segment_from_hash(connecting_peer_hash);
        if is_excluded(&deps.location_index, &qualified_prefix, ctx, &peer_seg) {
            tracing::debug!(
                context = ctx,
                peer_seg = %peer_seg,
                "policy resolver: connecting peer is layer-2 excluded"
            );
            return None;
        }
    }

    match policy.unknown_peer.as_str() {
        MODE_ANONYMOUS_DENY => None,
        MODE_ANONYMOUS_ALLOW => {
            let ctx = require_policy_field(
                policy.default_context.as_deref(),
                "default_context",
                MODE_ANONYMOUS_ALLOW,
            )?;
            let role = require_policy_field(
                policy.default_role.as_deref(),
                "default_role",
                MODE_ANONYMOUS_ALLOW,
            )?;
            read_role_def_grants(
                &deps.content_store,
                &deps.location_index,
                &deps.local_peer_id,
                ctx,
                role,
            )
        }
        MODE_RECOGNIZE_ON_ATTESTATION => {
            let ctx = require_policy_field(
                policy.default_context.as_deref(),
                "default_context",
                MODE_RECOGNIZE_ON_ATTESTATION,
            )?;
            let role = require_policy_field(
                policy.default_role.as_deref(),
                "default_role",
                MODE_RECOGNIZE_ON_ATTESTATION,
            )?;
            // Recognition requires a configured trusted_quorum. If
            // peer-config is unbound, recognition is impossible —
            // fall back per identity_required.
            let recognized = match read_trusted_quorum(
                &deps.content_store,
                &deps.location_index,
                &deps.local_peer_id,
            ) {
                Some(trusted_quorum) => recognize_identity_cert(
                    &deps.attestation_index,
                    &deps.content_store,
                    &deps.location_index,
                    connecting_peer_hash,
                    &trusted_quorum,
                    DEFAULT_MAX_CHAIN_DEPTH,
                    None,
                ),
                None => false,
            };
            if recognized {
                return read_role_def_grants(
                    &deps.content_store,
                    &deps.location_index,
                    &deps.local_peer_id,
                    ctx,
                    role,
                );
            }
            if policy.identity_required {
                None
            } else {
                read_role_def_grants(
                    &deps.content_store,
                    &deps.location_index,
                    &deps.local_peer_id,
                    ctx,
                    role,
                )
            }
        }
        // Unknown mode → fail closed (HANDOFF §6).
        _ => None,
    }
}

/// Return `Some(field)` if present; otherwise emit a warning naming the
/// missing policy field and the mode that requires it, and return None.
/// The shipped security model (positive + negative tests) depends on
/// `default_context` + `default_role` being set when `unknown_peer` is
/// anything other than `anonymous-deny`; the silent `None` short-circuit
/// is the only sharp edge in that posture, so we flag it loudly.
fn require_policy_field<'a>(
    field: Option<&'a str>,
    field_name: &'static str,
    mode: &'static str,
) -> Option<&'a str> {
    if field.is_none() {
        tracing::warn!(
            mode,
            field = field_name,
            "policy resolver: {field_name} is absent but unknown_peer = {mode}; no grants will be conferred",
        );
    }
    field
}
