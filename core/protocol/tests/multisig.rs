//! Cross-impl test vectors for PROPOSAL-MULTISIG-CORE-PRIMITIVE §12.
//!
//! Each `#[test]` corresponds to a row in the proposal's table of 23 scenarios.
//! These run against the local Rust verifier; the same scenarios also drive
//! the cross-impl `probe-multisig` validator (see `cmd/probe-multisig/`) when
//! exercising Go/Python peers.

use std::collections::{BTreeMap, HashMap};

use entity_capability::{
    capability_path_for_multisig_root, decode_granter, encode_granter, CapabilityToken,
    DelegationCaveats, GrantEntry, Granter, IdScope, MultiGranter, PathScope,
};
use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_protocol::{
    check_creator_authority, verify_capability_chain, ProtocolError,
};
use entity_types::{PeerData, SignatureData, TYPE_CAP_TOKEN};

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

struct Identity {
    keypair: Keypair,
    entity: Entity,
    hash: Hash,
    peer_id: String,
}

fn make_identity_from_seed(seed: u8) -> Identity {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    let keypair = Keypair::from_seed(bytes);
    let peer_id = keypair.peer_id().to_string();
    let identity_data = PeerData {
        public_key: keypair.public_key_bytes().to_vec(),
        key_type: "ed25519".into(),
    };
    let entity = identity_data.to_entity().unwrap();
    let hash = entity.content_hash;
    Identity {
        keypair,
        entity,
        hash,
        peer_id,
    }
}

/// Build a capability entity from a `CapabilityToken`. Uses the public ECF
/// encoder, including the polymorphic granter encoding (M8).
fn make_cap_entity(token: &CapabilityToken) -> Entity {
    token.to_entity().unwrap()
}

fn sign_entity(keypair: &Keypair, signer: Hash, target: Hash) -> Entity {
    let signature = keypair.sign(&target.to_bytes());
    SignatureData {
        target,
        signer,
        algorithm: "ed25519".into(),
        signature: signature.to_vec(),
    }
    .to_entity()
    .unwrap()
}

fn ms_grants() -> Vec<GrantEntry> {
    vec![GrantEntry {
        handlers: PathScope::all(),
        resources: PathScope::all(),
        operations: IdScope::all(),
        peers: Some(IdScope::all()),
        constraints: None,
        allowances: None,
    }]
}

/// Frame-invariant variant of [`ms_grants`] — resources use the cross-peer
/// `/*/*` form (absolute, V7 §5.5 frame-invariant) instead of bare `*`.
///
/// Required for a multi-hop delegation chain whose links have **different
/// granters**: under V7 §5.5a per-link granter-frame attenuation a bare `*`
/// canonicalizes against each link's own granter (`/{granter}/*`) and breaks
/// transitively (b's `*` = `/{b}/*` is not ⊆ alice's `*` = `/{alice}/*`).
/// `/*/*` is already absolute, so it canonicalizes identically at every link
/// and expresses "full authority that survives re-delegation."
fn ms_grants_xpeer() -> Vec<GrantEntry> {
    vec![GrantEntry {
        handlers: PathScope::all(),
        resources: PathScope::new(vec!["/*/*".into()]),
        operations: IdScope::all(),
        peers: Some(IdScope::all()),
        constraints: None,
        allowances: None,
    }]
}

fn included_btree(entries: Vec<Entity>) -> BTreeMap<Hash, Entity> {
    let mut m = BTreeMap::new();
    for e in entries {
        m.insert(e.content_hash, e);
    }
    m
}

fn included_hash(entries: Vec<Entity>) -> HashMap<Hash, Entity> {
    let mut m = HashMap::new();
    for e in entries {
        m.insert(e.content_hash, e);
    }
    m
}

// ---------------------------------------------------------------------------
// Vector 1 — Single-sig regression
// ---------------------------------------------------------------------------

#[test]
fn vec1_single_sig_valid_chain_allow() {
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(alice.hash),
        grantee: bob.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    let sig = sign_entity(&alice.keypair, alice.hash, cap.content_hash);
    let included = included_btree(vec![alice.entity.clone(), bob.entity, cap.clone(), sig]);
    assert!(verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).is_ok());
}

// ---------------------------------------------------------------------------
// Vectors 2–4, 13–14 — Multi-sig threshold semantics (M4 + M6)
// ---------------------------------------------------------------------------

#[test]
fn vec2_multisig_2of3_two_valid_sigs_allow() {
    // Local peer (alice) is one of the signers and signed.
    let alice = make_identity_from_seed(1);
    let cold1 = make_identity_from_seed(2);
    let _cold2 = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);

    let multi = MultiGranter {
        signers: vec![alice.hash, cold1.hash, _cold2.hash],
        threshold: 2,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    let sig_alice = sign_entity(&alice.keypair, alice.hash, cap.content_hash);
    let sig_cold1 = sign_entity(&cold1.keypair, cold1.hash, cap.content_hash);
    let included = included_btree(vec![
        alice.entity.clone(),
        cold1.entity,
        _cold2.entity,
        grantee.entity,
        cap.clone(),
        sig_alice,
        sig_cold1,
    ]);
    assert!(verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).is_ok());
}

#[test]
fn vec3_multisig_2of3_one_valid_sig_deny() {
    let alice = make_identity_from_seed(1);
    let cold1 = make_identity_from_seed(2);
    let cold2 = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);
    let multi = MultiGranter {
        signers: vec![alice.hash, cold1.hash, cold2.hash],
        threshold: 2,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    // Only Alice signs.
    let sig_alice = sign_entity(&alice.keypair, alice.hash, cap.content_hash);
    let included = included_btree(vec![
        alice.entity.clone(),
        cold1.entity,
        cold2.entity,
        grantee.entity,
        cap.clone(),
        sig_alice,
    ]);
    let err = verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).unwrap_err();
    assert!(matches!(err, ProtocolError::InvalidSignature));
}

#[test]
fn vec4_multisig_2of3_three_valid_sigs_allow() {
    let alice = make_identity_from_seed(1);
    let cold1 = make_identity_from_seed(2);
    let cold2 = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);
    let multi = MultiGranter {
        signers: vec![alice.hash, cold1.hash, cold2.hash],
        threshold: 2,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    let s1 = sign_entity(&alice.keypair, alice.hash, cap.content_hash);
    let s2 = sign_entity(&cold1.keypair, cold1.hash, cap.content_hash);
    let s3 = sign_entity(&cold2.keypair, cold2.hash, cap.content_hash);
    let included = included_btree(vec![
        alice.entity.clone(),
        cold1.entity,
        cold2.entity,
        grantee.entity,
        cap.clone(),
        s1,
        s2,
        s3,
    ]);
    assert!(verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).is_ok());
}

#[test]
fn vec14_multisig_3of3_all_signed_allow() {
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let carol = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);
    let multi = MultiGranter {
        signers: vec![alice.hash, bob.hash, carol.hash],
        threshold: 3,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    let s1 = sign_entity(&alice.keypair, alice.hash, cap.content_hash);
    let s2 = sign_entity(&bob.keypair, bob.hash, cap.content_hash);
    let s3 = sign_entity(&carol.keypair, carol.hash, cap.content_hash);
    let included = included_btree(vec![
        alice.entity.clone(),
        bob.entity,
        carol.entity,
        grantee.entity,
        cap.clone(),
        s1,
        s2,
        s3,
    ]);
    assert!(verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).is_ok());
}

// ---------------------------------------------------------------------------
// Vectors 5–10 — M3 content validity
// ---------------------------------------------------------------------------

#[test]
fn vec5_multisig_with_parent_deny() {
    // parent: Some(...) on a multi-sig cap MUST be rejected (M3). To exercise
    // the M3 check directly (vs. having chain-walk reachability fire first),
    // the parent is constructed as a reachable single-sig root.
    let alice = make_identity_from_seed(1);
    let cold1 = make_identity_from_seed(2);
    let cold2 = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);

    // Reachable single-sig parent rooted at alice.
    let parent_token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(alice.hash),
        grantee: alice.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let parent_cap = make_cap_entity(&parent_token);
    let s_parent = sign_entity(&alice.keypair, alice.hash, parent_cap.content_hash);

    // Multi-sig cap with parent: Some — illegal per M3.
    let multi = MultiGranter {
        signers: vec![alice.hash, cold1.hash, cold2.hash],
        threshold: 2,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: Some(parent_cap.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    let s1 = sign_entity(&alice.keypair, alice.hash, cap.content_hash);
    let s2 = sign_entity(&cold1.keypair, cold1.hash, cap.content_hash);
    let included = included_btree(vec![
        alice.entity.clone(),
        cold1.entity,
        cold2.entity,
        grantee.entity,
        parent_cap,
        cap.clone(),
        s_parent,
        s1,
        s2,
    ]);
    let err = verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).unwrap_err();
    // Per follow-up #4: M3 violations MUST surface as
    // CapabilityInvalid → 403 capability_denied at the wire boundary.
    assert!(
        matches!(err, ProtocolError::CapabilityInvalid(_)),
        "expected CapabilityInvalid (→403), got: {err:?}"
    );
    assert!(err.is_auth_error(), "M3 violation must classify as auth-error");
    let msg = format!("{}", err);
    assert!(
        msg.contains("multi-sig") && msg.contains("parent"),
        "expected M3 parent rejection message, got: {msg}"
    );
}

#[test]
fn vec6_multisig_k_equals_1_deny() {
    let m = MultiGranter {
        signers: vec![Hash::zero(), Hash::compute("t", b"x")],
        threshold: 1,
    };
    assert!(m.validate().is_err());
}

#[test]
fn vec7_multisig_k_equals_0_deny() {
    let m = MultiGranter {
        signers: vec![Hash::zero(), Hash::compute("t", b"x")],
        threshold: 0,
    };
    assert!(m.validate().is_err());
}

#[test]
fn vec8_multisig_k_greater_than_n_deny() {
    let m = MultiGranter {
        signers: vec![Hash::zero(), Hash::compute("t", b"x")],
        threshold: 3,
    };
    assert!(m.validate().is_err());
}

#[test]
fn vec9_multisig_duplicate_signers_deny() {
    let h = Hash::compute("t", b"dup");
    let m = MultiGranter {
        signers: vec![h, h],
        threshold: 2,
    };
    assert!(m.validate().is_err());
}

#[test]
fn vec10_multisig_n_equals_1_deny() {
    let m = MultiGranter {
        signers: vec![Hash::zero()],
        threshold: 2,
    };
    assert!(m.validate().is_err());
}

// ---------------------------------------------------------------------------
// Vectors 11–12 — M6 root-trust enforcement
// ---------------------------------------------------------------------------

#[test]
fn vec11_multisig_local_peer_not_in_signers_deny() {
    // A 2-of-3 cap that doesn't include the verifying peer in `signers`.
    // K-of-N alone passes; M6 requires the local peer be a constituent AND
    // have signed.
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let carol = make_identity_from_seed(3);
    let stranger = make_identity_from_seed(7); // local peer for verification
    let grantee = make_identity_from_seed(9);

    let multi = MultiGranter {
        signers: vec![alice.hash, bob.hash, carol.hash],
        threshold: 2,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    let s1 = sign_entity(&alice.keypair, alice.hash, cap.content_hash);
    let s2 = sign_entity(&bob.keypair, bob.hash, cap.content_hash);
    let included = included_btree(vec![
        alice.entity,
        bob.entity,
        carol.entity,
        grantee.entity,
        cap.clone(),
        s1,
        s2,
    ]);
    let err =
        verify_capability_chain(&cap.content_hash, &included, &stranger.peer_id).unwrap_err();
    assert!(matches!(err, ProtocolError::NotLocalPeer));
}

#[test]
fn vec12_multisig_local_peer_in_signers_but_not_signed_deny() {
    // Alice is in `signers` but did NOT sign — bob & carol did. Threshold met,
    // but M6 rejects because the local peer (alice) didn't sign.
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let carol = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);

    let multi = MultiGranter {
        signers: vec![alice.hash, bob.hash, carol.hash],
        threshold: 2,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    let s_bob = sign_entity(&bob.keypair, bob.hash, cap.content_hash);
    let s_carol = sign_entity(&carol.keypair, carol.hash, cap.content_hash);
    let included = included_btree(vec![
        alice.entity.clone(),
        bob.entity,
        carol.entity,
        grantee.entity,
        cap.clone(),
        s_bob,
        s_carol,
    ]);
    let err = verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).unwrap_err();
    assert!(matches!(err, ProtocolError::NotLocalPeer));
}

// ---------------------------------------------------------------------------
// Vectors 15–17 — M7 strict-with-signature
// ---------------------------------------------------------------------------

#[test]
fn vec15_creator_authority_single_sig_writer_match() {
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(alice.hash),
        grantee: bob.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    let store: HashMap<Hash, Entity> = [
        (cap.content_hash, cap.clone()),
        (alice.entity.content_hash, alice.entity.clone()),
    ]
    .into();
    let included = included_hash(vec![]);
    let res = check_creator_authority(&cap.content_hash, &alice.hash, &included, |h| {
        store.get(h).cloned()
    })
    .unwrap();
    assert!(res.found);
}

#[test]
fn vec16_creator_authority_multisig_in_signers_and_signed_found() {
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let carol = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);
    let multi = MultiGranter {
        signers: vec![alice.hash, bob.hash, carol.hash],
        threshold: 2,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    let s_alice = sign_entity(&alice.keypair, alice.hash, cap.content_hash);
    let s_bob = sign_entity(&bob.keypair, bob.hash, cap.content_hash);
    // ctx.included carries the cap + signatures (envelope-scoped lookups).
    let included = included_hash(vec![cap.clone(), s_alice, s_bob]);
    // Resolver looks up identity entities (envelope first, store fallback).
    let store: HashMap<Hash, Entity> = [
        (alice.entity.content_hash, alice.entity.clone()),
        (bob.entity.content_hash, bob.entity.clone()),
    ]
    .into();
    let res = check_creator_authority(&cap.content_hash, &alice.hash, &included, |h| {
        included.get(h).cloned().or_else(|| store.get(h).cloned())
    })
    .unwrap();
    assert!(res.found);
}

#[test]
fn vec17_creator_authority_multisig_in_signers_didnt_sign_not_found() {
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let carol = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);
    let multi = MultiGranter {
        signers: vec![alice.hash, bob.hash, carol.hash],
        threshold: 2,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    // Only bob and carol sign.
    let s_bob = sign_entity(&bob.keypair, bob.hash, cap.content_hash);
    let s_carol = sign_entity(&carol.keypair, carol.hash, cap.content_hash);
    let included = included_hash(vec![cap.clone(), s_bob, s_carol]);
    let store: HashMap<Hash, Entity> = [
        (alice.entity.content_hash, alice.entity.clone()),
        (bob.entity.content_hash, bob.entity.clone()),
        (carol.entity.content_hash, carol.entity.clone()),
    ]
    .into();
    let res = check_creator_authority(&cap.content_hash, &alice.hash, &included, |h| {
        included.get(h).cloned().or_else(|| store.get(h).cloned())
    })
    .unwrap();
    assert!(!res.found, "alice in signers but didn't sign — strict-with-sig rejects");
}

// ---------------------------------------------------------------------------
// Vectors 18a/18b/18c — wire encoding (M8 structural distinction, no tags)
// ---------------------------------------------------------------------------

#[test]
fn vec18a_granter_bstr_decodes_as_single() {
    let h = Hash::compute("t", b"identity");
    let encoded = encode_granter(&Granter::Single(h));
    let cbor = entity_ecf::to_ecf(&encoded);
    let decoded_value: ciborium::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
    let g = decode_granter(&decoded_value).unwrap();
    match g {
        Granter::Single(out) => assert_eq!(out, h),
        Granter::Multi(_) => panic!("expected single, got multi"),
    }
}

#[test]
fn vec18b_granter_map_decodes_as_multi() {
    let m = MultiGranter {
        signers: vec![Hash::compute("t", b"a"), Hash::compute("t", b"b")],
        threshold: 2,
    };
    let encoded = encode_granter(&Granter::Multi(m.clone()));
    let cbor = entity_ecf::to_ecf(&encoded);
    let decoded_value: ciborium::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
    let g = decode_granter(&decoded_value).unwrap();
    match g {
        Granter::Multi(out) => {
            assert_eq!(out.signers, m.signers);
            assert_eq!(out.threshold, m.threshold);
        }
        Granter::Single(_) => panic!("expected multi, got single"),
    }
}

#[test]
fn vec18c_granter_with_cbor_tag_rejected() {
    // Construct a CBOR-tagged value (any tag — ENTITY-CBOR-ENCODING.md §11
    // forbids tags on data fields universally). Test vector #18c.
    let h = Hash::compute("t", b"identity");
    let inner = ciborium::Value::Bytes(h.to_bytes().to_vec());
    let tagged = ciborium::Value::Tag(42, Box::new(inner));
    let err = decode_granter(&tagged).unwrap_err();
    assert!(format!("{err}").contains("CBOR-tagged"));
}

// ---------------------------------------------------------------------------
// Vector 19 / 19b — M10 attenuation across multi-sig root + downstream
// ---------------------------------------------------------------------------

#[test]
fn vec19_multisig_root_with_single_sig_child_allow() {
    // Multi-sig root + one downstream single-sig cap; child grants ⊆ root.
    let alice = make_identity_from_seed(1);
    let cold1 = make_identity_from_seed(2);
    let _cold2 = make_identity_from_seed(3);
    let bob = make_identity_from_seed(9);

    let multi = MultiGranter {
        signers: vec![alice.hash, cold1.hash, _cold2.hash],
        threshold: 2,
    };
    // Root grantee = alice (so alice can issue the child).
    let root_token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: alice.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let root = make_cap_entity(&root_token);
    let sig_alice = sign_entity(&alice.keypair, alice.hash, root.content_hash);
    let sig_cold1 = sign_entity(&cold1.keypair, cold1.hash, root.content_hash);

    let child_token = CapabilityToken {
        grants: ms_grants(), // ⊆ root
        granter: Granter::Single(alice.hash),
        grantee: bob.hash,
        parent: Some(root.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let child = make_cap_entity(&child_token);
    let sig_child = sign_entity(&alice.keypair, alice.hash, child.content_hash);

    let included = included_btree(vec![
        alice.entity.clone(),
        cold1.entity,
        _cold2.entity,
        bob.entity,
        root,
        child.clone(),
        sig_alice,
        sig_cold1,
        sig_child,
    ]);
    assert!(verify_capability_chain(&child.content_hash, &included, &alice.peer_id).is_ok());
}

#[test]
fn vec19b_multisig_root_with_three_single_sig_links_allow() {
    // V7 §5.5a (per-link granter-frame attenuation): this legitimate 3-hop
    // delegation chain (alice → b → c → d, each re-granting full authority)
    // uses the frame-invariant `/*/*` resource form via `ms_grants_xpeer`.
    // Bare `*` would canonicalize against each link's own granter and break
    // the chain (b's `*` = `/{b}/*` ⊄ alice's `/{alice}/*`) — see
    // `ms_grants_xpeer`. The negative case (foreign bare-`*` re-delegation
    // MUST deny) is locked by `vec19c_foreign_granter_bare_wildcard_chain_deny`.
    let alice = make_identity_from_seed(1);
    let cold1 = make_identity_from_seed(2);
    let _cold2 = make_identity_from_seed(3);
    let b = make_identity_from_seed(11);
    let c = make_identity_from_seed(12);
    let d = make_identity_from_seed(13);

    let multi = MultiGranter {
        signers: vec![alice.hash, cold1.hash, _cold2.hash],
        threshold: 2,
    };
    let root_token = CapabilityToken {
        grants: ms_grants_xpeer(),
        granter: Granter::Multi(multi),
        grantee: alice.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let root = make_cap_entity(&root_token);
    let s_root_alice = sign_entity(&alice.keypair, alice.hash, root.content_hash);
    let s_root_cold1 = sign_entity(&cold1.keypair, cold1.hash, root.content_hash);

    // alice → b
    let l1_token = CapabilityToken {
        grants: ms_grants_xpeer(),
        granter: Granter::Single(alice.hash),
        grantee: b.hash,
        parent: Some(root.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let l1 = make_cap_entity(&l1_token);
    let s_l1 = sign_entity(&alice.keypair, alice.hash, l1.content_hash);

    // b → c
    let l2_token = CapabilityToken {
        grants: ms_grants_xpeer(),
        granter: Granter::Single(b.hash),
        grantee: c.hash,
        parent: Some(l1.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let l2 = make_cap_entity(&l2_token);
    let s_l2 = sign_entity(&b.keypair, b.hash, l2.content_hash);

    // c → d (leaf)
    let l3_token = CapabilityToken {
        grants: ms_grants_xpeer(),
        granter: Granter::Single(c.hash),
        grantee: d.hash,
        parent: Some(l2.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let l3 = make_cap_entity(&l3_token);
    let s_l3 = sign_entity(&c.keypair, c.hash, l3.content_hash);

    let included = included_btree(vec![
        alice.entity.clone(),
        cold1.entity,
        _cold2.entity,
        b.entity,
        c.entity,
        d.entity,
        root,
        l1,
        l2,
        l3.clone(),
        s_root_alice,
        s_root_cold1,
        s_l1,
        s_l2,
        s_l3,
    ]);
    assert!(verify_capability_chain(&l3.content_hash, &included, &alice.peer_id).is_ok());
}

/// V7 §5.5a / §PR-8 (V1' chain-walk surface) — the negative case vec19b's
/// positive case is paired with. A foreign-granted **bare `*`** mid link, with
/// a leaf that explicitly targets the verifier's namespace, MUST be denied at
/// the chain-walk: the mid's `*` canonicalizes against its own granter A
/// (`/{A}/*`), so the leaf's `/{V}/some/path` is NOT ⊆ the mid. Under the
/// pre-fix bug the mid's `*` canonicalized against the verifier (`/{V}/*`) and
/// the leaf passed — the V1' authority escalation. Mirrors the validate-peer
/// `authz_attenuation_foreign_granter_1` vector in-tree.
#[test]
fn vec19c_foreign_granter_bare_wildcard_chain_deny() {
    let v = make_identity_from_seed(20); // verifier (= chain root granter, local peer)
    let a = make_identity_from_seed(21); // foreign mid granter
    let bb = make_identity_from_seed(22); // foreign leaf granter
    let g = make_identity_from_seed(23); // final grantee

    // root: granter = V (local), grantee = A, frame-invariant /*/* (admits).
    let root_token = CapabilityToken {
        grants: ms_grants_xpeer(),
        granter: Granter::Single(v.hash),
        grantee: a.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let root = make_cap_entity(&root_token);
    let s_root = sign_entity(&v.keypair, v.hash, root.content_hash);

    // mid: granter = A (foreign), grantee = B, bare `*` → /{A}/* per §5.5.
    let mid_token = CapabilityToken {
        grants: ms_grants(), // bare `*` — frame-dependent on granter A
        granter: Granter::Single(a.hash),
        grantee: bb.hash,
        parent: Some(root.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let mid = make_cap_entity(&mid_token);
    let s_mid = sign_entity(&a.keypair, a.hash, mid.content_hash);

    // leaf: granter = B (foreign), grantee = G, EXPLICIT path in V's namespace.
    let leaf_grants = vec![GrantEntry {
        handlers: PathScope::all(),
        resources: PathScope::new(vec![format!("/{}/some/path", v.peer_id)]),
        operations: IdScope::all(),
        peers: Some(IdScope::all()),
        constraints: None,
        allowances: None,
    }];
    let leaf_token = CapabilityToken {
        grants: leaf_grants,
        granter: Granter::Single(bb.hash),
        grantee: g.hash,
        parent: Some(mid.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let leaf = make_cap_entity(&leaf_token);
    let s_leaf = sign_entity(&bb.keypair, bb.hash, leaf.content_hash);

    let included = included_btree(vec![
        v.entity.clone(),
        a.entity,
        bb.entity,
        g.entity,
        root,
        mid,
        leaf.clone(),
        s_root,
        s_mid,
        s_leaf,
    ]);
    // leaf `/{V}/some/path` ⊄ mid `/{A}/*` → AttenuationViolation.
    assert!(matches!(
        verify_capability_chain(&leaf.content_hash, &included, &v.peer_id),
        Err(ProtocolError::AttenuationViolation)
    ));
}

// ---------------------------------------------------------------------------
// Vectors 20/21 — Storage path (M12). Tree-binding lookup is is_revoked
// territory (out of scope for verify_capability_chain). We assert the path
// helper produces the spec-mandated convention.
// ---------------------------------------------------------------------------

#[test]
fn vec20_21_multisig_root_storage_path() {
    let h = Hash::compute("t", b"some-cap");
    let path = capability_path_for_multisig_root(&h);
    assert!(
        path.starts_with("system/capability/grants/multi-sig-root/"),
        "{path}"
    );
    // The cap_hash component is the protocol display form (V7 §1.2).
    assert!(path.contains("ecfv1-sha256:"), "{path}");
}

// ---------------------------------------------------------------------------
// Vectors 22/23 — Connection-time delivery (V7 §4.4) follows the same M6 rule
// as in-band caps. No special carve-out. Functionally identical to vec2/vec12.
// ---------------------------------------------------------------------------

#[test]
fn vec22_connection_time_multisig_receiver_signed_allow() {
    // Same shape as vec2 — a multi-sig cap delivered during HELLO/IDENTIFY
    // is verified by the same routine. There is no carve-out for §4.4.
    vec2_multisig_2of3_two_valid_sigs_allow();
}

#[test]
fn vec23_connection_time_multisig_receiver_didnt_sign_deny() {
    vec12_multisig_local_peer_in_signers_but_not_signed_deny();
}

// ---------------------------------------------------------------------------
// Vectors 24a/24b — Status normalization (PROPOSAL §3.3 / §10.1,
// follow-up #4): every M3 violation surfaces as CapabilityInvalid → 403
// capability_denied, regardless of which K-range value tripped the check.
// ---------------------------------------------------------------------------

fn run_chain_walk_with_k_threshold(k: u64) -> ProtocolError {
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let carol = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);
    let multi = MultiGranter {
        signers: vec![alice.hash, bob.hash, carol.hash],
        threshold: k,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    // Attach two valid signatures so M4 alone wouldn't fail (for K∈[2,3]) —
    // the only failure path is M3.
    let s1 = sign_entity(&alice.keypair, alice.hash, cap.content_hash);
    let s2 = sign_entity(&bob.keypair, bob.hash, cap.content_hash);
    let included = included_btree(vec![
        alice.entity.clone(),
        bob.entity,
        carol.entity,
        grantee.entity,
        cap.clone(),
        s1,
        s2,
    ]);
    verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).unwrap_err()
}

#[test]
fn vec24_k_zero_surfaces_as_capability_invalid() {
    let err = run_chain_walk_with_k_threshold(0);
    assert!(
        matches!(err, ProtocolError::CapabilityInvalid(_)),
        "K=0 must classify as CapabilityInvalid (→403), got: {err:?}"
    );
    assert!(err.is_auth_error());
}

#[test]
fn vec24_k_one_surfaces_as_capability_invalid() {
    let err = run_chain_walk_with_k_threshold(1);
    assert!(
        matches!(err, ProtocolError::CapabilityInvalid(_)),
        "K=1 must classify as CapabilityInvalid (→403), got: {err:?}"
    );
    assert!(err.is_auth_error());
}

#[test]
fn vec24_k_greater_than_n_surfaces_as_capability_invalid() {
    let err = run_chain_walk_with_k_threshold(99);
    assert!(
        matches!(err, ProtocolError::CapabilityInvalid(_)),
        "K>N must classify as CapabilityInvalid (→403), got: {err:?}"
    );
    assert!(err.is_auth_error());
}

// ---------------------------------------------------------------------------
// Vectors 25a/25b — Within-cap precedence (PROPOSAL §3.3 follow-up #4):
// M3 MUST fire before signature verification on the same cap. When a cap
// has both M3 violations AND signature defects, M3 is what surfaces.
// ---------------------------------------------------------------------------

#[test]
fn vec25a_m3_beats_missing_sigs() {
    // K > N (M3) AND zero K-of-N signatures attached. Without precedence,
    // a verifier might surface MissingSignature/InvalidSignature; with
    // precedence, M3's CapabilityInvalid wins.
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let carol = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);
    let multi = MultiGranter {
        signers: vec![alice.hash, bob.hash, carol.hash],
        threshold: 99, // M3 violation: K > N
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    // No signatures attached — M4 would fail below threshold.
    let included = included_btree(vec![
        alice.entity.clone(),
        bob.entity,
        carol.entity,
        grantee.entity,
        cap.clone(),
    ]);
    let err = verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).unwrap_err();
    assert!(
        matches!(err, ProtocolError::CapabilityInvalid(_)),
        "M3 must fire before missing-sig check, got: {err:?}"
    );
}

#[test]
fn vec25b_m3_beats_invalid_sigs() {
    // K > N (M3) AND attached signatures are valid in shape but on the
    // wrong target. Without precedence, sig verification might surface
    // InvalidSignature; with precedence, M3's CapabilityInvalid wins.
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let carol = make_identity_from_seed(3);
    let grantee = make_identity_from_seed(9);
    let multi = MultiGranter {
        signers: vec![alice.hash, bob.hash, carol.hash],
        threshold: 99, // M3 violation
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(multi),
        grantee: grantee.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let cap = make_cap_entity(&token);
    // Signatures targeting the wrong hash.
    let wrong_target = Hash::compute("test", b"wrong-target");
    let bad1 = sign_entity(&alice.keypair, alice.hash, wrong_target);
    let bad2 = sign_entity(&bob.keypair, bob.hash, wrong_target);
    let included = included_btree(vec![
        alice.entity.clone(),
        bob.entity,
        carol.entity,
        grantee.entity,
        cap.clone(),
        bad1,
        bad2,
    ]);
    let err = verify_capability_chain(&cap.content_hash, &included, &alice.peer_id).unwrap_err();
    assert!(
        matches!(err, ProtocolError::CapabilityInvalid(_)),
        "M3 must fire before invalid-sig check, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Bonus: round-trip a multi-sig CapabilityToken through entity encode/decode.
// Catches encode/decode parity bugs that vec18a/b miss at the granter-only
// layer.
// ---------------------------------------------------------------------------

#[test]
fn token_with_multi_granter_roundtrips() {
    let m = MultiGranter {
        signers: vec![
            Hash::compute("t", b"a"),
            Hash::compute("t", b"b"),
            Hash::compute("t", b"c"),
        ],
        threshold: 2,
    };
    let token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Multi(m.clone()),
        grantee: Hash::compute("t", b"grantee"),
        parent: None,
        created_at: 100,
        expires_at: Some(200),
        not_before: None,
        delegation_caveats: Some(DelegationCaveats {
            no_delegation: Some(true),
            max_delegation_depth: None,
            max_delegation_ttl: None,
        }),
    };
    let entity = token.to_entity().unwrap();
    assert_eq!(entity.entity_type, TYPE_CAP_TOKEN);
    let decoded = CapabilityToken::from_entity(&entity).unwrap();
    assert_eq!(decoded.granter, Granter::Multi(m));
    assert_eq!(decoded.grantee, token.grantee);
    assert_eq!(decoded.created_at, 100);
    assert_eq!(decoded.expires_at, Some(200));
}

// ---------------------------------------------------------------------------
// Sanity: the M8 ECF encoding of single-sig caps is unchanged (backward
// compat per §10.4).
// ---------------------------------------------------------------------------

#[test]
fn single_sig_encoding_is_byte_string_not_map() {
    let h = Hash::compute("t", b"granter");
    let enc = encode_granter(&Granter::Single(h));
    let cbor = entity_ecf::to_ecf(&enc);
    let v: ciborium::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
    assert!(v.as_bytes().is_some(), "single-sig granter must encode as CBOR bstr");
}

// ---------------------------------------------------------------------------
// Chain enforcement F-vectors (V7 §5.5 / §5.7). Cross-impl parity with the
// Go F1–F6 attenuation set: caps the verifier MUST deny. Pre-fix these were
// accepted (200) because the per-link delegation-caveat + temporal checks
// were not wired into the chain walk.
// ---------------------------------------------------------------------------

fn now_ms_test() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// F: a child delegated from a parent with `no_delegation: true` MUST deny.
#[test]
fn chain_no_delegation_denied() {
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);

    // Single-sig root, granted by the local peer (alice), self-grantee so
    // alice may issue the child. Carries no_delegation: true.
    let root_token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(alice.hash),
        grantee: alice.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: Some(DelegationCaveats {
            no_delegation: Some(true),
            max_delegation_depth: None,
            max_delegation_ttl: None,
        }),
    };
    let root = make_cap_entity(&root_token);
    let s_root = sign_entity(&alice.keypair, alice.hash, root.content_hash);

    let child_token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(alice.hash),
        grantee: bob.hash,
        parent: Some(root.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let child = make_cap_entity(&child_token);
    let s_child = sign_entity(&alice.keypair, alice.hash, child.content_hash);

    let included = included_btree(vec![
        alice.entity.clone(),
        bob.entity,
        root,
        child.clone(),
        s_root,
        s_child,
    ]);
    let err = verify_capability_chain(&child.content_hash, &included, &alice.peer_id)
        .expect_err("child of a no_delegation parent MUST be denied");
    assert!(matches!(err, ProtocolError::CapabilityInvalid(_)), "got {err:?}");
}

/// F: a child whose lifetime exceeds the parent's `max_delegation_ttl` MUST
/// deny. The child is itself temporally valid (expires in the future) so the
/// only thing rejecting it is the caveat.
#[test]
fn chain_max_delegation_ttl_denied() {
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let now = now_ms_test();

    let root_token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(alice.hash),
        grantee: alice.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: Some(DelegationCaveats {
            no_delegation: None,
            max_delegation_depth: None,
            max_delegation_ttl: Some(1_000), // 1s max
        }),
    };
    let root = make_cap_entity(&root_token);
    let s_root = sign_entity(&alice.keypair, alice.hash, root.content_hash);

    // child lifetime = 10s > 1s cap, while still valid now.
    let child_token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(alice.hash),
        grantee: bob.hash,
        parent: Some(root.content_hash),
        created_at: now,
        expires_at: Some(now + 10_000),
        not_before: None,
        delegation_caveats: None,
    };
    let child = make_cap_entity(&child_token);
    let s_child = sign_entity(&alice.keypair, alice.hash, child.content_hash);

    let included = included_btree(vec![
        alice.entity.clone(),
        bob.entity,
        root,
        child.clone(),
        s_root,
        s_child,
    ]);
    let err = verify_capability_chain(&child.content_hash, &included, &alice.peer_id)
        .expect_err("child lifetime exceeding max_delegation_ttl MUST be denied");
    assert!(matches!(err, ProtocolError::CapabilityInvalid(_)), "got {err:?}");
}

/// F: a chain with a not-yet-valid intermediate link MUST deny, even when the
/// leaf itself is currently valid. Pre-fix only the leaf's temporal bounds
/// were checked.
#[test]
fn chain_per_link_temporal_denied() {
    let alice = make_identity_from_seed(1);
    let bob = make_identity_from_seed(2);
    let carol = make_identity_from_seed(3);
    let now = now_ms_test();

    let root_token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(alice.hash),
        grantee: alice.hash,
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let root = make_cap_entity(&root_token);
    let s_root = sign_entity(&alice.keypair, alice.hash, root.content_hash);

    // Intermediate link is not valid until far in the future.
    let mid_token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(alice.hash),
        grantee: bob.hash,
        parent: Some(root.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: Some(now + 1_000_000),
        delegation_caveats: None,
    };
    let mid = make_cap_entity(&mid_token);
    let s_mid = sign_entity(&alice.keypair, alice.hash, mid.content_hash);

    // Leaf is valid right now — only the intermediate is not-yet-valid.
    let leaf_token = CapabilityToken {
        grants: ms_grants(),
        granter: Granter::Single(bob.hash),
        grantee: carol.hash,
        parent: Some(mid.content_hash),
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let leaf = make_cap_entity(&leaf_token);
    let s_leaf = sign_entity(&bob.keypair, bob.hash, leaf.content_hash);

    let included = included_btree(vec![
        alice.entity.clone(),
        bob.entity,
        carol.entity,
        root,
        mid,
        leaf.clone(),
        s_root,
        s_mid,
        s_leaf,
    ]);
    let err = verify_capability_chain(&leaf.content_hash, &included, &alice.peer_id)
        .expect_err("not-yet-valid intermediate link MUST be denied");
    assert!(matches!(err, ProtocolError::CapabilityNotYetValid), "got {err:?}");
}
