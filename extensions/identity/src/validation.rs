//! Identity-specific validators per EXTENSION-IDENTITY v3.2 §3.6.
//!
//! `identity_topology_for`, `identity_is_quorum_link`,
//! `identity_is_authorized_revoker`, `identity_verify_cert`. The
//! mechanics (signature verify, supersedes walks, K-of-N) live in the
//! substrate primitives; this module orchestrates them with identity
//! rules.

use std::collections::HashMap;
use std::sync::Arc;

use entity_attestation::{
    find_revocations_for, is_attestation_live,
    verify_attestation_signature, verify_specific_signer, walk_attesting_chain_default,
    AttestationCtx, AttestationData, AttestationIndex,
};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_quorum::{
    current_signer_set, is_quorum_id, verify_k_of_n_signatures, QuorumCtx,
    ResolverRegistry, SignerSetCache,
};
use entity_store::{ContentStore, LocationIndex};

use crate::kinds::{
    identity_lifecycle_kinds, valid_functions, Function, KIND_IDENTITY_CERT,
    KIND_IDENTITY_RETIREMENT, KIND_IDENTITY_ROTATION_HANDOFF,
    KIND_IDENTITY_ROTATION_RECOVERY,
};

/// Topology dispatch result (§3.6 `identity_topology_for`).
#[derive(Debug, Clone)]
pub enum Topology {
    /// Single-sig from `expected_signer`. The substrate's
    /// `verify_attestation_signature` covers the default case
    /// (signer = att.attesting); this variant is used when the expected
    /// signer is explicitly named.
    Single { expected_signer: Hash },
    /// Dual-sig (e.g., `identity-rotation-handoff`).
    Dual { signers: Vec<Hash> },
    /// K-of-N (top-level controller cert; rotation-recovery; retirement).
    KofN { signers: Vec<Hash>, threshold: u64 },
}

/// Identity-context bundle. Combines the attestation primitive's ctx
/// plus quorum primitive's ctx for K-of-N dispatch.
pub struct IdentityCtx<'a> {
    pub attestation_index: &'a AttestationIndex,
    pub content_store: &'a Arc<dyn ContentStore>,
    pub location_index: &'a Arc<dyn LocationIndex>,
    pub included: &'a HashMap<Hash, Entity>,
    pub resolver_registry: &'a ResolverRegistry,
    pub signer_set_cache: &'a SignerSetCache,
}

impl<'a> IdentityCtx<'a> {
    pub fn attestation_ctx(&self) -> AttestationCtx<'a> {
        AttestationCtx {
            index: self.attestation_index,
            content_store: self.content_store,
            location_index: self.location_index,
            included: self.included,
        }
    }

    pub fn quorum_ctx(&self) -> QuorumCtx<'a> {
        QuorumCtx {
            attestation_index: self.attestation_index,
            content_store: self.content_store,
            location_index: self.location_index,
            included: self.included,
            resolver_registry: self.resolver_registry,
            signer_set_cache: self.signer_set_cache,
        }
    }
}

// ===========================================================================
// §3.6 helpers
// ===========================================================================

/// `lookup_target_cert` per §3.6 — resolves a `properties.target_cert`
/// reference (from a lifecycle event) to the cert entity it targets.
pub fn lookup_target_cert(att: &AttestationData, ctx: &IdentityCtx) -> Option<AttestationData> {
    let target = att
        .properties
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("target_cert") { Some(v) } else { None })?;
    let bytes = target.as_bytes()?;
    let target_hash = Hash::from_bytes(bytes).ok()?;
    ctx.attestation_index.get(&target_hash)
}

/// `identity_is_quorum_link` per §3.6 — terminate predicate for chain
/// walks. True iff `att.attesting` refers to a `system/quorum` entity.
pub fn identity_is_quorum_link(att: &AttestationData, ctx: &IdentityCtx) -> bool {
    is_quorum_id(&att.attesting, &ctx.quorum_ctx())
}

/// Read `properties.function` from an attestation if present and
/// well-typed.
pub fn read_function(att: &AttestationData) -> Option<&str> {
    att.properties
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("function") { v.as_text() } else { None })
}

/// Read `properties.mode` from an attestation if present.
pub fn read_mode(att: &AttestationData) -> Option<&str> {
    att.properties
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("mode") { v.as_text() } else { None })
}

/// `identity_confers_function` per spec v3.3 §3.6 (SI-13). Returns `true`
/// iff `att` confers `function_name` on `att.attested`. Handles both
/// `identity-cert` (direct function field) and lifecycle kinds
/// (function inherited from target_cert via recursion).
/// `identity-retirement` returns `false` — the chain ends here as dead.
pub fn identity_confers_function(
    att: &AttestationData,
    function_name: &str,
    ctx: &IdentityCtx,
) -> bool {
    let kind = match att.kind() {
        Some(k) => k,
        None => return false,
    };
    match kind {
        KIND_IDENTITY_CERT => read_function(att) == Some(function_name),
        KIND_IDENTITY_ROTATION_HANDOFF | KIND_IDENTITY_ROTATION_RECOVERY => {
            // Rotation kinds confer the same function as the target cert.
            // Recurse to handle handoff-of-handoff / recovery-of-handoff cases.
            match lookup_target_cert(att, ctx) {
                Some(target) => identity_confers_function(&target, function_name, ctx),
                None => false,
            }
        }
        KIND_IDENTITY_RETIREMENT => false,
        _ => false,
    }
}

// ===========================================================================
// §3.6 identity_topology_for
// ===========================================================================

/// Topology dispatch per §3.6. Returns the signature-validation strategy
/// required for `att`. Returns `None` if the kind is not an
/// identity-context kind (caller treats as non-identity).
pub fn identity_topology_for(att: &AttestationData, ctx: &IdentityCtx) -> Option<Topology> {
    let kind = att.kind()?;
    let function = read_function(att);
    let function_enum = function.and_then(Function::parse_optional);

    match kind {
        KIND_IDENTITY_CERT => {
            match function_enum {
                Some(Function::Controller) => {
                    if identity_is_quorum_link(att, ctx) {
                        // Top-level controller cert — K-of-N from quorum.
                        let qctx = ctx.quorum_ctx();
                        let set = current_signer_set(&att.attesting, &qctx).ok()?;
                        Some(Topology::KofN {
                            signers: set.signers,
                            threshold: set.threshold,
                        })
                    } else {
                        // Sub-controller — single-sig from issuing controller.
                        Some(Topology::Single {
                            expected_signer: att.attesting,
                        })
                    }
                }
                Some(Function::Agent) | Some(Function::Identifier) => Some(Topology::Single {
                    expected_signer: att.attesting,
                }),
                None => {
                    // App-defined function — default single-sig per §4.2.
                    Some(Topology::Single {
                        expected_signer: att.attesting,
                    })
                }
            }
        }
        KIND_IDENTITY_ROTATION_HANDOFF => {
            // Dual-sig from old (att.attesting) and new (att.attested).
            Some(Topology::Dual {
                signers: vec![att.attesting, att.attested],
            })
        }
        KIND_IDENTITY_ROTATION_RECOVERY | KIND_IDENTITY_RETIREMENT => {
            // K-of-N from quorum — recovery/retirement are quorum-driven.
            let qctx = ctx.quorum_ctx();
            let set = current_signer_set(&att.attesting, &qctx).ok()?;
            Some(Topology::KofN {
                signers: set.signers,
                threshold: set.threshold,
            })
        }
        _ => None,
    }
}

// ===========================================================================
// §3.6 identity_is_authorized_revoker
// ===========================================================================

/// Identity rule: only the quorum at the root of `target_cert`'s chain
/// (or its constituents K-of-N) can revoke. Self-revocation is handled
/// at the primitive layer.
pub fn identity_is_authorized_revoker(
    revoker: &Hash,
    target_cert_hash: &Hash,
    target_cert: &AttestationData,
    ctx: &IdentityCtx,
) -> bool {
    let actx = ctx.attestation_ctx();
    let chain = walk_attesting_chain_default(target_cert_hash, target_cert, |a, c| {
        // closure lifetime: borrow of QuorumCtx can't outlive AttestationCtx;
        // re-derive locally using is_quorum_id against the same stores.
        is_quorum_id(&a.attesting, &QuorumCtx {
            attestation_index: c.index,
            content_store: c.content_store,
            location_index: c.location_index,
            included: c.included,
            resolver_registry: ctx.resolver_registry,
            signer_set_cache: ctx.signer_set_cache,
        })
    }, &actx);
    let chain = match chain {
        Some(c) => c,
        None => return false,
    };
    let quorum_id = match chain.last() {
        Some((_, a)) => a.attesting,
        None => return false,
    };
    revoker == &quorum_id
}

// ===========================================================================
// §3.6 identity_verify_cert — orchestration
// ===========================================================================

#[derive(Debug, thiserror::Error)]
pub enum VerifyCertError {
    #[error("not_identity_attestation")]
    NotIdentity,
    #[error("invalid_function")]
    InvalidFunction,
    #[error("invalid_signature")]
    InvalidSignature,
    #[error("not_live")]
    NotLive,
    #[error("authority_revoked")]
    AuthorityRevoked,
    #[error("k_of_n_failed")]
    KofNFailed,
    #[error("wrong_signer")]
    WrongSigner,
    #[error("missing_dual_sig: {0}")]
    MissingDualSig(String),
    #[error("chain_to_quorum_not_found")]
    ChainToQuorumNotFound,
    #[error("chain_link_invalid: {0}")]
    ChainLinkInvalid(String),
    #[error("topology_dispatch_failed: {0}")]
    TopologyDispatchFailed(String),
}

/// Diagnose why `identity_topology_for` returned `None` for a kind we
/// expected to dispatch. Per the cross-impl spec R-7'
/// (TV-CONFIGURE-TOPOLOGY-DISPATCH-DIAGNOSTICS): when topology dispatch
/// fails, the error subcode MUST be specific enough to identify which
/// step failed (quorum lookup, signer-set load, signer-resolution, etc).
/// Generic `topology_dispatch_failed` for a configure that has all the
/// prerequisites bound suggests an internal bug; specific subcodes help
/// cross-impl debugging.
fn diagnose_topology_failure(att: &AttestationData, ctx: &IdentityCtx) -> String {
    let kind = match att.kind() {
        Some(k) => k,
        None => return "missing_kind".into(),
    };
    let function = read_function(att);
    let function_enum = function.and_then(Function::parse_optional);
    let qctx = ctx.quorum_ctx();
    match (kind, function_enum) {
        (KIND_IDENTITY_CERT, Some(Function::Controller)) => {
            if !identity_is_quorum_link(att, ctx) {
                "controller_no_quorum_link_but_topology_for_returned_none_unexpected".into()
            } else {
                match current_signer_set(&att.attesting, &qctx) {
                    Ok(_) => "current_signer_set_ok_but_topology_for_returned_none_unexpected".into(),
                    Err(e) => format!("current_signer_set_failed: {}", e),
                }
            }
        }
        (KIND_IDENTITY_ROTATION_RECOVERY, _) | (KIND_IDENTITY_RETIREMENT, _) => {
            match current_signer_set(&att.attesting, &qctx) {
                Ok(_) => "current_signer_set_ok_but_topology_for_returned_none_unexpected".into(),
                Err(e) => format!("current_signer_set_failed: {}", e),
            }
        }
        (k, f) => format!("unhandled_kind_function: kind={} function={:?}", k, f),
    }
}

/// Orchestration entry point per §3.6. Composes primitive helpers +
/// identity rules.
pub fn identity_verify_cert(
    att_hash: &Hash,
    att: &AttestationData,
    ctx: &IdentityCtx,
) -> Result<(), VerifyCertError> {
    // Identity-specific structural validation.
    let kind = att.kind().ok_or(VerifyCertError::NotIdentity)?;
    let lifecycle = identity_lifecycle_kinds();
    if kind != KIND_IDENTITY_CERT && !lifecycle.contains(&kind) {
        return Err(VerifyCertError::NotIdentity);
    }
    if kind == KIND_IDENTITY_CERT {
        if let Some(f) = read_function(att) {
            // Standard function names accepted; app-defined accepted as
            // "any string." Reject only if function field is empty/missing.
            if f.is_empty() {
                return Err(VerifyCertError::InvalidFunction);
            }
            // Standard functions OR an app-defined string — both pass.
            let _ = valid_functions();
        } else {
            return Err(VerifyCertError::InvalidFunction);
        }
    }

    let actx = ctx.attestation_ctx();

    // Liveness check (generic).
    if !is_attestation_live(att_hash, att, &actx, None) {
        return Err(VerifyCertError::NotLive);
    }

    // Authority-revocation check (identity-specific rule).
    let revs = find_revocations_for(att_hash, &actx);
    for (r_hash, r) in &revs {
        if is_attestation_live(r_hash, r, &actx, None)
            && identity_is_authorized_revoker(&r.attesting, att_hash, att, ctx)
        {
            return Err(VerifyCertError::AuthorityRevoked);
        }
    }

    // Topology dispatch + validation.
    //
    // Per spec ambiguity ATT-2 (logged in docs/SPEC-AMBIGUITIES.md): §3.6's
    // pseudocode runs `verify_attestation_signature` (single-sig from
    // `att.attesting`) before topology dispatch, but for top-level
    // controller certs `att.attesting` is the quorum_id — which has no
    // keypair, so the single-sig check necessarily fails. We reorder to
    // dispatch on topology first; signature validation runs in the
    // topology-appropriate variant.
    let topology = match identity_topology_for(att, ctx) {
        Some(t) => t,
        None => {
            return Err(VerifyCertError::TopologyDispatchFailed(
                diagnose_topology_failure(att, ctx),
            ));
        }
    };
    match topology {
        Topology::KofN { signers, threshold } => {
            let qctx = ctx.quorum_ctx();
            if !verify_k_of_n_signatures(att_hash, &signers, threshold, &qctx) {
                return Err(VerifyCertError::KofNFailed);
            }
        }
        Topology::Single { expected_signer } => {
            if att.attesting != expected_signer {
                return Err(VerifyCertError::WrongSigner);
            }
            if !verify_attestation_signature(att_hash, att, &actx) {
                return Err(VerifyCertError::InvalidSignature);
            }
        }
        Topology::Dual { signers } => {
            for signer in &signers {
                if !verify_specific_signer(att_hash, att, signer, &actx) {
                    return Err(VerifyCertError::MissingDualSig(format!("{:?}", signer)));
                }
            }
        }
    }

    // Chain walk back to quorum (for non-top-level certs).
    if !identity_is_quorum_link(att, ctx) {
        let resolver_registry = ctx.resolver_registry;
        let signer_set_cache = ctx.signer_set_cache;
        let chain = walk_attesting_chain_default(
            att_hash,
            att,
            |a, c| {
                is_quorum_id(
                    &a.attesting,
                    &QuorumCtx {
                        attestation_index: c.index,
                        content_store: c.content_store,
                        location_index: c.location_index,
                        included: c.included,
                        resolver_registry,
                        signer_set_cache,
                    },
                )
            },
            &actx,
        );
        let chain = chain.ok_or(VerifyCertError::ChainToQuorumNotFound)?;
        // Validate every link in the chain (excluding `att` itself which
        // we already validated above).
        for (link_hash, link) in chain.iter().skip(1) {
            if let Err(e) = identity_verify_cert_no_chain(link_hash, link, ctx) {
                return Err(VerifyCertError::ChainLinkInvalid(format!("{}", e)));
            }
        }
    }

    Ok(())
}

/// Variant that skips chain-walk recursion (used by chain-walking
/// callers to avoid infinite recursion through links).
fn identity_verify_cert_no_chain(
    att_hash: &Hash,
    att: &AttestationData,
    ctx: &IdentityCtx,
) -> Result<(), VerifyCertError> {
    let actx = ctx.attestation_ctx();
    if !is_attestation_live(att_hash, att, &actx, None) {
        return Err(VerifyCertError::NotLive);
    }
    let topology = match identity_topology_for(att, ctx) {
        Some(t) => t,
        None => {
            return Err(VerifyCertError::TopologyDispatchFailed(
                diagnose_topology_failure(att, ctx),
            ));
        }
    };
    match topology {
        Topology::KofN { signers, threshold } => {
            let qctx = ctx.quorum_ctx();
            if !verify_k_of_n_signatures(att_hash, &signers, threshold, &qctx) {
                return Err(VerifyCertError::KofNFailed);
            }
        }
        Topology::Single { expected_signer } => {
            if att.attesting != expected_signer {
                return Err(VerifyCertError::WrongSigner);
            }
            if !verify_attestation_signature(att_hash, att, &actx) {
                return Err(VerifyCertError::InvalidSignature);
            }
        }
        Topology::Dual { signers } => {
            for signer in &signers {
                if !verify_specific_signer(att_hash, att, signer, &actx) {
                    return Err(VerifyCertError::MissingDualSig(format!("{:?}", signer)));
                }
            }
        }
    }
    Ok(())
}

// ===========================================================================
// §3.6 walk_cert_chain_to_current_controller
// ===========================================================================

/// Per §3.6 (spec v3.3 / SI-5 helper fix + SI-13 lifecycle-kind awareness)
/// — given an identity reference (typically a quorum_id), returns the
/// live cert that confers the controller function on its attested peer,
/// with deterministic tie-break across multi-controller deployments.
///
/// Predicate uses `identity_confers_function` so handoff/recovery
/// lifecycle attestations rooted at the quorum count too: a chain
/// `cert_v1 → handoff → handoff` validly resolves to the most-recent
/// handoff's `attested` peer.
pub fn walk_cert_chain_to_current_controller(
    quorum_id: &Hash,
    ctx: &IdentityCtx,
) -> Option<(Hash, AttestationData)> {
    let actx = ctx.attestation_ctx();
    let candidates = entity_attestation::find_attestations_by(
        quorum_id,
        |a| identity_confers_function_no_ctx(a, "controller"),
        &actx,
    );
    // Refine with full ctx-aware confers-function check (handles lifecycle
    // kinds whose function is inherited from target_cert).
    let confers: Vec<_> = candidates
        .into_iter()
        .filter(|(_, a)| identity_confers_function(a, "controller", ctx))
        .collect();
    let live: Vec<_> = confers
        .into_iter()
        .filter(|(h, a)| is_attestation_live(h, a, &actx, None))
        .collect();
    if live.is_empty() {
        return None;
    }
    if live.len() == 1 {
        return live.into_iter().next();
    }
    live.into_iter().min_by_key(|(h, _)| *h)
}

/// Cheap pre-filter for `find_attestations_by` predicate: checks
/// kind/function fields directly without a ctx-bound recursion. Used to
/// keep the index lookup fast; the expensive ctx-aware check happens on
/// the smaller filtered set.
fn identity_confers_function_no_ctx(att: &AttestationData, function_name: &str) -> bool {
    let kind = match att.kind() {
        Some(k) => k,
        None => return false,
    };
    match kind {
        KIND_IDENTITY_CERT => read_function(att) == Some(function_name),
        // For lifecycle kinds we can't resolve the target without ctx;
        // accept and let the post-filter validate.
        KIND_IDENTITY_ROTATION_HANDOFF | KIND_IDENTITY_ROTATION_RECOVERY => true,
        _ => false,
    }
}
