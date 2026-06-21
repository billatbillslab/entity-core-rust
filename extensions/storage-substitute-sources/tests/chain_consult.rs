//! Smoke tests for the chain-consult algorithm's control flow.
//!
//! Spec-shaped conformance tests (TV-SS-CORE-1..7, TV-SS-COMP-1..4 et al.)
//! land alongside cross-impl validate-peer wiring. This file confirms
//! the v1 algorithm short-circuits, error mappings, and the cap-axis
//! grant check (per the named-capability-mapping ruling) in
//! isolation.

use std::sync::Arc;

use entity_capability::{
    CapabilityToken, GrantEntry, Granter, IdScope, PathScope, ResourceTarget,
};
use entity_hash::Hash;
use entity_storage_substitute_sources::{
    ChainConsultHook, ConsultMiss, SubstituteConsultHook,
};
use entity_handler::{ExecuteFn, ExecuteOptions, HandlerError, HandlerResult};
use entity_store::{MemoryContentStore, MemoryLocationIndex};

const LOCAL_PEER: &str = "peer-A";

fn fake_hash(byte: u8) -> Hash {
    let mut digest = [0u8; 32];
    digest[0] = byte;
    Hash::new(0, digest)
}

fn nop_execute_fn() -> ExecuteFn {
    Arc::new(|_handler, _op, _params, _opts: ExecuteOptions| {
        Box::pin(async move {
            // Never called in these short-circuit tests; if it is, fail.
            Err::<HandlerResult, HandlerError>(HandlerError::Internal(
                "execute_fn unexpectedly called in short-circuit test".to_string(),
            ))
        })
    })
}

fn build_hook() -> ChainConsultHook {
    let content_store: Arc<dyn entity_store::ContentStore> =
        Arc::new(MemoryContentStore::default());
    let location_index: Arc<dyn entity_store::LocationIndex> =
        Arc::new(MemoryLocationIndex::default());
    ChainConsultHook::new(content_store, location_index, LOCAL_PEER)
}

fn fake_id_hash() -> Hash {
    Hash::new(0, [0u8; 32])
}

/// Mint a capability token holding a single grant. Used as the source
/// of "what the caller presents" in the cap-axis tests below.
fn token_with_grant(grant: GrantEntry) -> CapabilityToken {
    CapabilityToken {
        grants: vec![grant],
        granter: Granter::Single(fake_id_hash()),
        grantee: fake_id_hash(),
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    }
}

fn properly_scoped_consult_grant() -> GrantEntry {
    GrantEntry {
        handlers: PathScope::new(vec!["system/substitute/sources".into()]),
        resources: PathScope::new(vec![]),
        operations: IdScope::new(vec!["consult".into()]),
        peers: Some(IdScope::new(vec![LOCAL_PEER.into()])),
        constraints: None,
        allowances: None,
    }
}

#[tokio::test]
async fn bare_hash_query_short_circuits() {
    // TV-SS-BARE-1: query without claimed_source_peer_id → chain NOT
    // consulted; immediate NotResolved (CONTENT translates to 404).
    let hook = build_hook();
    let cap = token_with_grant(properly_scoped_consult_grant());

    let target = fake_hash(0x11);
    let result = hook
        .consult(&target, None, Some(&cap), None, &nop_execute_fn())
        .await;

    assert_eq!(result, Err(ConsultMiss::NoClaimedSource));
}

#[tokio::test]
async fn missing_cap_token_denies() {
    // RULING §6: fail-closed. No capability token → CapDenied BEFORE
    // any chain enumeration.
    let hook = build_hook();
    let target = fake_hash(0x22);
    let source = fake_hash(0x33);
    let result = hook
        .consult(&target, Some(&source), None, None, &nop_execute_fn())
        .await;
    assert_eq!(result, Err(ConsultMiss::CapDenied));
}

#[tokio::test]
async fn wrong_handler_grant_denies() {
    // Cap on a different handler (system/tree) must NOT permit consult.
    // This is the regression test for the prior "any-token" bug.
    let hook = build_hook();
    let grant = GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![]),
        operations: IdScope::new(vec!["consult".into()]),
        peers: Some(IdScope::new(vec![LOCAL_PEER.into()])),
        constraints: None,
        allowances: None,
    };
    let cap = token_with_grant(grant);
    let target = fake_hash(0x44);
    let source = fake_hash(0x55);

    let result = hook
        .consult(&target, Some(&source), Some(&cap), None, &nop_execute_fn())
        .await;
    assert_eq!(result, Err(ConsultMiss::CapDenied));
}

#[tokio::test]
async fn wrong_operation_grant_denies() {
    // Cap on the right handler but the wrong operation (e.g., a "get"
    // grant on system/substitute/sources) must not permit "consult".
    let hook = build_hook();
    let grant = GrantEntry {
        handlers: PathScope::new(vec!["system/substitute/sources".into()]),
        resources: PathScope::new(vec![]),
        operations: IdScope::new(vec!["get".into()]),
        peers: Some(IdScope::new(vec![LOCAL_PEER.into()])),
        constraints: None,
        allowances: None,
    };
    let cap = token_with_grant(grant);
    let target = fake_hash(0x66);
    let source = fake_hash(0x77);

    let result = hook
        .consult(&target, Some(&source), Some(&cap), None, &nop_execute_fn())
        .await;
    assert_eq!(result, Err(ConsultMiss::CapDenied));
}

#[tokio::test]
async fn properly_scoped_grant_no_resource_falls_through_to_disabled() {
    // Cap matches (handler, operation); chain is empty → falls through
    // to Disabled. Confirms the cap check itself passes — we get past
    // the gate but find no entries.
    let hook = build_hook();
    let cap = token_with_grant(properly_scoped_consult_grant());
    let target = fake_hash(0x88);
    let source = fake_hash(0x99);

    let result = hook
        .consult(&target, Some(&source), Some(&cap), None, &nop_execute_fn())
        .await;
    assert_eq!(result, Err(ConsultMiss::Disabled));
}

#[tokio::test]
async fn resource_outside_grant_scope_denies() {
    // Resource axis: grant scoped to namespace /peer-A/ns/permitted; a
    // consult against /peer-A/ns/other must not match.
    let hook = build_hook();
    let grant = GrantEntry {
        handlers: PathScope::new(vec!["system/substitute/sources".into()]),
        resources: PathScope::new(vec![format!("/{}/ns/permitted", LOCAL_PEER)]),
        operations: IdScope::new(vec!["consult".into()]),
        peers: Some(IdScope::new(vec![LOCAL_PEER.into()])),
        constraints: None,
        allowances: None,
    };
    let cap = token_with_grant(grant);
    let target = fake_hash(0xAA);
    let source = fake_hash(0xBB);

    let bad_resource = ResourceTarget {
        targets: vec![format!("/{}/ns/other", LOCAL_PEER)],
        exclude: vec![],
    };

    let result = hook
        .consult(
            &target,
            Some(&source),
            Some(&cap),
            Some(&bad_resource),
            &nop_execute_fn(),
        )
        .await;
    assert_eq!(result, Err(ConsultMiss::CapDenied));
}

#[tokio::test]
async fn empty_chain_returns_disabled() {
    // No entries installed under `system/substitute/sources/...` →
    // substrate returns Disabled (CONTENT maps to NotResolved → push
    // to `missing`). Cap check passes; the empty chain is the
    // downstream signal.
    let hook = build_hook();
    let cap = token_with_grant(properly_scoped_consult_grant());

    let target = fake_hash(0xCC);
    let source = fake_hash(0xDD);
    let result = hook
        .consult(&target, Some(&source), Some(&cap), None, &nop_execute_fn())
        .await;

    assert_eq!(result, Err(ConsultMiss::Disabled));
}
