//! Re-attenuation mint helper for cross-peer continuation dispatch.
//!
//! EXTENSION-CONTINUATION §4.2 case 3 / §8.2 C-3 — the SDK "re-attenuation
//! mint helper". Produces the dispatch_capability shape that satisfies *all
//! three* gates of a cross-peer continuation step whose `target` is a remote
//! peer B. These are the three independent identity slots of the V7 §5.2
//! "cross-peer capability provenance" model (which collapse onto one identity
//! only in the local case — the source of the v1.9→v1.11 corrections):
//!
//! - **(i) Root — B's advance-time `VerifyChain`** (V7 §5.2/§5.5). The chain
//!   must root at an authority B recognizes. We anchor the minted cap's
//!   `parent` at `parent` (a cap B already conferred on the installer,
//!   typically the connection grant), so the chain terminates B-rooted.
//! - **(ii) In-chain granter — the install-time in-chain check** (§3.1a /
//!   §3.2 step 4). The installer's identity must appear as a `granter`
//!   *anywhere in* the chain. The installer (`signer`) is the minted leaf's
//!   `granter`, so it does.
//! - **(iii) Grantee — B's `grantee == EXECUTE author` check** (V7 §5.2;
//!   spec v1.11 / Amendment 2). The cross-peer dispatched EXECUTE is authored
//!   by the continuation's **host peer** (the handler signs with that peer's
//!   keypair — the only key it holds), so the cap MUST be granted to the
//!   host peer. `grantee` is therefore an **explicit parameter** — NOT
//!   self-wielded to the installer (the v1.9 gap: B rejects
//!   `grantee != author` whenever installer ≠ host peer, i.e. every
//!   cross-peer continuation).
//!
//! Resulting chain: `leaf(granter=installer, grantee=host_peer,
//! parent=parent) → parent → … → root B recognizes`. Rooting the chain *at
//! the installer* — or self-wielding the grantee *to the installer* — is the
//! local sufficient condition only and is **wrong** cross-peer; this is the
//! dispatch-capability collapse the spec warns about (§4.2 case 3).

use entity_crypto::Keypair;
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_hash::Hash;
use thiserror::Error;

use crate::{CapabilityToken, GrantEntry, Granter};

/// Errors from [`mint_reattenuated`].
#[derive(Debug, Error)]
pub enum MintError {
    /// `parent` had a zero content hash — there is no B-recognized root to
    /// anchor the chain at, so the result would fail B's `VerifyChain`.
    #[error("mint_reattenuated: parent capability is required (the B-recognized root anchor)")]
    MissingParent,
    /// `grantee` had a zero content hash — §4.2 case 3 (iii) requires the
    /// grantee to be the dispatching host peer (the EXECUTE author); a zero
    /// grantee can never satisfy B's `grantee == author` check.
    #[error(
        "mint_reattenuated: grantee is required (the dispatching host peer / \
         EXECUTE author — §4.2 case 3 (iii))"
    )]
    MissingGrantee,
    /// `grants` was empty — a dispatch_capability with no grant entries
    /// authorizes nothing.
    #[error("mint_reattenuated: at least one grant entry is required")]
    EmptyGrants,
    /// Building the capability or signature entity failed.
    #[error("mint_reattenuated: {0}")]
    Build(String),
}

/// Mint a re-attenuated capability for cross-peer continuation dispatch
/// (EXTENSION-CONTINUATION §4.2 case 3 / §8.2 C-3).
///
/// The minted cap's `parent` is `parent` — a capability the target peer B
/// already recognizes (typically the connection grant B conferred on the
/// installer at connect). `signer` (the installer) is the re-attenuation
/// **leaf granter** (slot ii). `grantee` is the identity that will **wield**
/// the cap (slot iii): the continuation's dispatching **host peer**, which
/// authors the dispatched EXECUTE. So the authority chain is rooted at B's
/// conferred authority, with the installer in-chain as the leaf granter, and
/// granted to the host peer — satisfying all of: B's advance-time
/// `VerifyChain` incl. `grantee == author` (V7 §5.2) and the install-time
/// in-chain check (§3.1a).
///
/// `grantee` MUST be the dispatching host peer, **not** self-wielded to the
/// installer: the installer is the caller/admin that set the continuation up,
/// but the dispatcher is structurally the host peer (the only key the
/// continuation handler holds). Self-wielding to the installer is the v1.9
/// gap Amendment 2 (spec v1.11) closes — B rejects `grantee != author`
/// whenever installer ≠ host peer, i.e. every cross-peer continuation. The
/// installer knows the host peer's identity at install time (it is installing
/// onto that peer).
///
/// `grants` MUST be an attenuation of the parent's grants (the caller is
/// responsible for narrowing scope; this helper does not re-validate
/// attenuation — B's `VerifyChain` does that at advance). For prefix
/// operations (`tree.extract`/`tree.merge` over `prefix/`) scope to the
/// subtree (`prefix/*`), not the bare literal, or B returns 403. `expires_at`
/// SHOULD inherit / not exceed the parent's expiry (V7 §5.6) — likewise the
/// caller's responsibility.
///
/// Returns `(cap_entity, sig_entity)`: the capability entity and its detached
/// signature (the same canonical 4-field signature shape the wire codec and
/// envelope ingest expect). The caller stores both and bundles the full chain
/// — via [`crate`]-adjacent `collect_chain_bundle` — into the dispatched
/// envelope's `included` per §4.3 chain transport.
pub fn mint_reattenuated(
    signer: &Keypair,
    signer_identity: &Entity,
    grantee: Hash,
    parent: &Entity,
    grants: Vec<GrantEntry>,
    created_at: u64,
    expires_at: Option<u64>,
) -> Result<(Entity, Entity), MintError> {
    if parent.content_hash.is_zero() {
        return Err(MintError::MissingParent);
    }
    if grantee.is_zero() {
        return Err(MintError::MissingGrantee);
    }
    if grants.is_empty() {
        return Err(MintError::EmptyGrants);
    }

    let token = CapabilityToken {
        grants,
        // (ii) in-chain leaf granter = the installer (`signer`).
        granter: Granter::single(signer_identity.content_hash),
        // (iii) grantee = the dispatching host peer (the EXECUTE author),
        // NOT self-wielded to the installer — §4.2 case 3 (iii), v1.11.
        grantee,
        parent: Some(parent.content_hash),
        created_at,
        expires_at,
        not_before: None,
        delegation_caveats: None,
    };

    let cap_entity = token
        .to_entity()
        .map_err(|e| MintError::Build(format!("build cap entity: {e}")))?;

    let sig_bytes = signer.sign(&cap_entity.content_hash.to_bytes());
    let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
        (
            entity_ecf::text("signature"),
            entity_ecf::Value::Bytes(sig_bytes.to_vec()),
        ),
        (
            entity_ecf::text("signer"),
            entity_ecf::Value::Bytes(signer_identity.content_hash.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("target"),
            entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
        ),
    ]));
    let sig_entity = Entity::new(TYPE_SIGNATURE, sig_data)
        .map_err(|e| MintError::Build(format!("build signature entity: {e}")))?;

    Ok((cap_entity, sig_entity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PathScope;

    // Build a B→grantee root cap entity (no parent) for use as the anchor.
    fn root_cap(b_keypair: &Keypair, b_hash: entity_hash::Hash, grantee: entity_hash::Hash) -> Entity {
        let token = CapabilityToken {
            grants: vec![GrantEntry {
                handlers: PathScope::new(vec!["system/tree".into()]),
                operations: crate::IdScope::new(vec!["put".into()]),
                resources: PathScope::new(vec!["/peer_b/data/*".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            }],
            granter: Granter::single(b_hash),
            grantee,
            parent: None,
            created_at: 1000,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        let _ = b_keypair; // root signature not needed for these structural tests
        token.to_entity().unwrap()
    }

    /// §4.2 case 3 shape (v1.11): the minted chain is ROOTED AT B's conferred
    /// authority (i), the installer is the in-chain leaf GRANTER (ii), and the
    /// cap is GRANTED TO the dispatching host peer (iii) — NOT self-wielded to
    /// the installer (the v1.9 gap Amendment 2 closes) and NOT rooted at the
    /// installer (the original cross-peer-breaking shape §4.2 warns about).
    #[test]
    fn test_mint_reattenuated_shape() {
        let b_kp = Keypair::generate();
        let inst_kp = Keypair::generate();
        let host_kp = Keypair::generate(); // peer A — the dispatching host peer
        let b_id = b_kp.peer_entity().unwrap();
        let inst_id = inst_kp.peer_entity().unwrap();
        let host_id = host_kp.peer_entity().unwrap();

        // B confers authority on the installer: granter=B, no parent → B-rooted.
        let conn_cap = root_cap(&b_kp, b_id.content_hash, inst_id.content_hash);

        let attenuated = vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            operations: crate::IdScope::new(vec!["put".into()]),
            resources: PathScope::new(vec!["/peer_b/data/shared/*".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }];

        let (cap, sig) = mint_reattenuated(
            &inst_kp,
            &inst_id,
            host_id.content_hash, // (iii) grantee = the dispatching host peer
            &conn_cap,
            attenuated,
            2000,
            None,
        )
        .unwrap();

        // Leaf: granter=installer (ii), grantee=host peer (iii),
        // parent=conn_cap (B-rooted, i).
        let leaf = CapabilityToken::from_entity(&cap).unwrap();
        assert_eq!(
            leaf.granter.as_single(),
            Some(&inst_id.content_hash),
            "installer MUST be the leaf granter (ii — the §3.1a in-chain anchor)"
        );
        assert_eq!(
            leaf.grantee, host_id.content_hash,
            "(iii) grantee MUST be the dispatching host peer (the EXECUTE author)"
        );
        assert_ne!(
            leaf.grantee, inst_id.content_hash,
            "(iii) grantee MUST NOT be self-wielded to the installer (the v1.9 gap)"
        );
        assert_eq!(
            leaf.parent,
            Some(conn_cap.content_hash),
            "leaf MUST chain to B's conferred authority (B-rooted), NOT root at the installer"
        );

        // The root of the chain is the B-conferred cap whose granter is B.
        let root = CapabilityToken::from_entity(&conn_cap).unwrap();
        assert_eq!(
            root.granter.as_single(),
            Some(&b_id.content_hash),
            "chain MUST be rooted at B's conferred authority (root granter == B)"
        );
        assert_ne!(
            root.granter.as_single(),
            Some(&inst_id.content_hash),
            "chain MUST NOT be rooted at the installer (the cross-peer-breaking shape)"
        );

        // Signature is over the cap content hash, signed by the installer.
        assert_eq!(sig.entity_type, TYPE_SIGNATURE);
        let sd = entity_types::SignatureData::from_entity(&sig).unwrap();
        assert_eq!(sd.target, cap.content_hash);
        assert_eq!(sd.signer, inst_id.content_hash);
        assert_eq!(sd.algorithm, "ed25519");
        assert!(
            Keypair::verify(
                &inst_kp.public_key_bytes(),
                &cap.content_hash.to_bytes(),
                &sd.signature,
            )
            .is_ok(),
            "leaf signature must verify under the installer key"
        );
    }

    #[test]
    fn test_mint_reattenuated_rejects_bad_input() {
        let inst_kp = Keypair::generate();
        let inst_id = inst_kp.peer_entity().unwrap();
        let g = vec![GrantEntry {
            handlers: PathScope::new(vec![]),
            operations: crate::IdScope::new(vec!["put".into()]),
            resources: PathScope::new(vec![]),
            peers: None,
            constraints: None,
            allowances: None,
        }];

        let grantee = inst_id.content_hash; // any non-zero stand-in host peer

        // Zero-hash parent → no B-recognized anchor.
        let mut zero_parent =
            Entity::new("x", entity_ecf::to_ecf(&entity_ecf::Value::Null)).unwrap();
        zero_parent.content_hash = entity_hash::Hash::zero();
        assert!(matches!(
            mint_reattenuated(&inst_kp, &inst_id, grantee, &zero_parent, g.clone(), 1, None),
            Err(MintError::MissingParent)
        ));

        let parent = root_cap(&inst_kp, inst_id.content_hash, inst_id.content_hash);

        // Zero-hash grantee → can never satisfy B's `grantee == author`.
        assert!(matches!(
            mint_reattenuated(
                &inst_kp,
                &inst_id,
                entity_hash::Hash::zero(),
                &parent,
                g.clone(),
                1,
                None
            ),
            Err(MintError::MissingGrantee)
        ));

        // Empty grants.
        assert!(matches!(
            mint_reattenuated(&inst_kp, &inst_id, grantee, &parent, vec![], 1, None),
            Err(MintError::EmptyGrants)
        ));
    }
}
