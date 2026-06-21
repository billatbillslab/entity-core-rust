//! EXTENSION-DISCOVERY v1.0 entity-codec tests (§2.1, §2.2.1, §3).
//!
//! Round-trips, the wire-shape invariants the interop pitfalls call out
//! (bare 33-byte `system/hash` fields; `peer_id` absent-not-null when unknown),
//! the §2.2.1 fail-closed admission gate, and cohort-stable byte-equal
//! content-hash fixtures (the cross-impl convergence pins).

use entity_ecf::{text, Value};
use entity_hash::Hash;

use crate::data::*;

// A literal 33-byte `system/hash` (format 0x00 SHA-256 + 32-byte digest) for
// fixtures that reference another entity by hash without chaining to a computed
// value — keeps the byte-equal pins self-contained and Go/Py-reproducible.
fn lit_hash(fill: u8) -> Hash {
    Hash::new(0x00, [fill; 32])
}

// ---------------------------------------------------------------------------
// Round-trips
// ---------------------------------------------------------------------------

#[test]
fn candidate_tofu_round_trip() {
    let c = CandidateData {
        peer_id: None,
        backend: "mdns".into(),
        observed_at: 1_700_000_000_000,
        endpoint_hint: text("192.168.1.42:7777"),
        identity_hint: None,
        supersedes: None,
    };
    let e = c.to_entity().unwrap();
    assert_eq!(CandidateData::from_entity(&e).unwrap(), c);
}

#[test]
fn candidate_successor_round_trip() {
    // candidate_1: peer_id populated post-IDENTIFY, supersedes candidate_0,
    // identity_hint pins an IdentityClaim (§2.2).
    let c = CandidateData {
        peer_id: Some("z6MkDiscoveryTestPeer".into()),
        backend: "mdns".into(),
        observed_at: 1_700_000_000_500,
        endpoint_hint: Value::Map(vec![
            (text("host"), text("192.168.1.42")),
            (text("port"), Value::Integer(7777.into())),
        ]),
        identity_hint: Some(lit_hash(0xAB)),
        supersedes: Some(lit_hash(0x11)),
    };
    let e = c.to_entity().unwrap();
    assert_eq!(CandidateData::from_entity(&e).unwrap(), c);
}

#[test]
fn decision_round_trip_grant_and_track() {
    let grant = DecisionData {
        candidate: lit_hash(0x22),
        outcome: crate::OUTCOME_GRANT_LIMITED.into(),
        grant: Some(lit_hash(0x33)),
        decided_at: 1_700_000_001_000,
    };
    let e = grant.to_entity().unwrap();
    assert_eq!(DecisionData::from_entity(&e).unwrap(), grant);

    // ignore/track carry no grant (None → absent).
    let track = DecisionData {
        candidate: lit_hash(0x22),
        outcome: crate::OUTCOME_TRACK.into(),
        grant: None,
        decided_at: 1_700_000_001_000,
    };
    let e = track.to_entity().unwrap();
    assert_eq!(DecisionData::from_entity(&e).unwrap(), track);
}

#[test]
fn identity_claim_round_trip() {
    let ic = IdentityClaimData {
        peer_id: "z6MkDiscoveryTestPeer".into(),
        key_type: 1,
        hash_type: 0,
        public_key_digest: vec![0xAB; 32],
    };
    let e = ic.to_entity().unwrap();
    assert_eq!(IdentityClaimData::from_entity(&e).unwrap(), ic);
}

// ---------------------------------------------------------------------------
// Wire-shape invariants (interop pitfalls)
// ---------------------------------------------------------------------------

fn decoded_data(data: &[u8]) -> Vec<(Value, Value)> {
    let v: Value = ciborium::from_reader(data).unwrap();
    v.into_map().unwrap()
}

fn field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| if k.as_text() == Some(key) { Some(v) } else { None })
}

#[test]
fn tofu_candidate_omits_peer_id_key() {
    // peer_id null-until-IDENTIFY is encoded ABSENT, not as an explicit null
    // (project-wide "optional SHOULD be absent" convention). A stray null key
    // would change the candidate's content_hash and silently break cross-impl
    // supersedes/decision references.
    let c = CandidateData {
        peer_id: None,
        backend: "mdns".into(),
        observed_at: 1_700_000_000_000,
        endpoint_hint: text("192.168.1.42:7777"),
        identity_hint: None,
        supersedes: None,
    };
    let map = decoded_data(&c.to_entity().unwrap().data);
    assert!(field(&map, "peer_id").is_none(), "peer_id must be absent, not null");
    assert!(field(&map, "identity_hint").is_none());
    assert!(field(&map, "supersedes").is_none());
}

#[test]
fn hash_fields_are_bare_33_byte_bstrs() {
    // identity_hint / supersedes / candidate / grant are bare `system/hash`
    // 33-byte byte strings, NOT {type,data,content_hash} maps.
    let c = CandidateData {
        peer_id: Some("z6MkP".into()),
        backend: "mdns".into(),
        observed_at: 1,
        endpoint_hint: text("x"),
        identity_hint: Some(lit_hash(0xAB)),
        supersedes: Some(lit_hash(0x11)),
    };
    let map = decoded_data(&c.to_entity().unwrap().data);
    for key in ["identity_hint", "supersedes"] {
        match field(&map, key) {
            Some(Value::Bytes(b)) => assert_eq!(b.len(), 33, "{key} must be 33-byte bstr"),
            other => panic!("{key} must be a bare byte string, got {other:?}"),
        }
    }

    let d = DecisionData {
        candidate: lit_hash(0x22),
        outcome: crate::OUTCOME_GRANT_MORE.into(),
        grant: Some(lit_hash(0x33)),
        decided_at: 1,
    };
    let map = decoded_data(&d.to_entity().unwrap().data);
    for key in ["candidate", "grant"] {
        match field(&map, key) {
            Some(Value::Bytes(b)) => assert_eq!(b.len(), 33, "{key} must be 33-byte bstr"),
            other => panic!("{key} must be a bare byte string, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// §2.2.1 fail-closed admission gate
// ---------------------------------------------------------------------------

#[test]
fn identity_claim_hash_gate() {
    // Post-IDENTIFY the receiver reconstructs the claim and compares hashes.
    // Same inputs → equal (admit); any field differs → not-equal (fail closed).
    let advertised = IdentityClaimData {
        peer_id: "z6MkDiscoveryTestPeer".into(),
        key_type: 1,
        hash_type: 0,
        public_key_digest: vec![0xAB; 32],
    }
    .content_hash()
    .unwrap();

    let identical = IdentityClaimData {
        peer_id: "z6MkDiscoveryTestPeer".into(),
        key_type: 1,
        hash_type: 0,
        public_key_digest: vec![0xAB; 32],
    }
    .content_hash()
    .unwrap();
    assert_eq!(advertised, identical, "matching claim must admit");

    let wrong_key = IdentityClaimData {
        peer_id: "z6MkDiscoveryTestPeer".into(),
        key_type: 1,
        hash_type: 0,
        public_key_digest: vec![0xCD; 32], // attacker substitutes a different key
    }
    .content_hash()
    .unwrap();
    assert_ne!(advertised, wrong_key, "mismatched claim MUST fail closed");
}

// ---------------------------------------------------------------------------
// ScanResult envelope (§3, §3.1)
// ---------------------------------------------------------------------------

#[test]
fn scan_result_ok_round_trip() {
    let r = ScanResult::ok(vec![lit_hash(0x01), lit_hash(0x02)]);
    assert!(!r.truncated);
    assert!(r.code.is_none());
    assert_eq!(ScanResult::from_value(&r.to_value()).unwrap(), r);
}

#[test]
fn scan_result_overflow_surfaces_code() {
    // §3.1 / §8.4: over-bound MUST surface truncated + code, never silent.
    let r = ScanResult::overflow(vec![lit_hash(0x01)]);
    assert!(r.truncated);
    assert_eq!(r.code.as_deref(), Some(crate::CODE_SCAN_OVERFLOW));
    assert_eq!(r.code.as_deref(), Some("discovery_scan_overflow"));
    assert_eq!(ScanResult::from_value(&r.to_value()).unwrap(), r);
}

// ---------------------------------------------------------------------------
// Cohort-stable byte-equal fixtures (cross-impl convergence pins)
// ---------------------------------------------------------------------------
//
// Fully literal inputs → deterministic content_hash. Go and Python MUST
// reproduce these exact hex digests; any divergence is a wire-shape splinter.
// (If ECF/encoding intentionally changes, re-pin here in the same commit.)

#[test]
fn fixture_candidate_tofu_hash() {
    let c = CandidateData {
        peer_id: None,
        backend: "mdns".into(),
        observed_at: 1_700_000_000_000,
        endpoint_hint: text("192.168.1.42:7777"),
        identity_hint: None,
        supersedes: None,
    };
    assert_eq!(
        c.to_entity().unwrap().content_hash.to_hex(),
        "00b613881ab1f301c47d1b567ba639d59c82a782df2ddaca0a1b0919da573fd1a4"
    );
}

#[test]
fn fixture_identity_claim_hash() {
    let ic = IdentityClaimData {
        peer_id: "z6MkDiscoveryTestPeer".into(),
        key_type: 1,
        hash_type: 0,
        public_key_digest: vec![0xAB; 32],
    };
    assert_eq!(
        ic.to_entity().unwrap().content_hash.to_hex(),
        "00e8faef6326ed153f08841fd4641db567c3d04bb59c077991a054e5faeaee1675"
    );
}

#[test]
fn fixture_decision_grant_limited_hash() {
    let d = DecisionData {
        candidate: lit_hash(0x22),
        outcome: crate::OUTCOME_GRANT_LIMITED.into(),
        grant: lit_hash(0x33).into(),
        decided_at: 1_700_000_001_000,
    };
    assert_eq!(
        d.to_entity().unwrap().content_hash.to_hex(),
        "00a621ad87d52e913d8d277bca02badd7c2261bca50c8664ec87c13cbbceb9e29e"
    );
}

// ---------------------------------------------------------------------------
// Handler tests over a mock backend (deterministic; no network) + a live
// two-daemon mDNS round-trip (#[ignore] — needs a multicast-capable network).
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
mod handler_tests {
    use std::sync::Arc;

    use entity_ecf::{text, to_ecf, Value};
    use entity_entity::Entity;
    use entity_handler::{Handler, HandlerContext};
    use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};

    use crate::backend::{AnnounceParams, DiscoveryBackend, Observation};
    use crate::data::CandidateData;
    use crate::handler::DiscoveryHandler;
    use crate::{candidate_prefix, DiscoveryError};

    const PEER: &str = "z6MkDiscoveryTestPeer";

    /// A deterministic in-memory backend that yields a fixed observation list.
    struct MockBackend {
        observations: Vec<Observation>,
    }

    #[async_trait::async_trait]
    impl DiscoveryBackend for MockBackend {
        fn name(&self) -> &str {
            "mock"
        }
        async fn scan(&self, _filter: Option<Value>) -> Result<Vec<Observation>, DiscoveryError> {
            Ok(self.observations.clone())
        }
        async fn announce(&self, _p: &AnnounceParams) -> Result<(), DiscoveryError> {
            Ok(())
        }
        async fn announce_stop(&self, _p: &str) -> Result<(), DiscoveryError> {
            Ok(())
        }
    }

    fn stores() -> (Arc<dyn ContentStore>, Arc<dyn LocationIndex>) {
        (
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
        )
    }

    fn scan_ctx(backend: &str) -> HandlerContext {
        let params = Entity::new(
            entity_types::TYPE_PROTOCOL_STATUS,
            to_ecf(&Value::Map(vec![(text("backend"), text(backend))])),
        )
        .unwrap();
        let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
        HandlerContext::builder(execute, params)
            .operation("scan".to_string())
            .build()
    }

    fn result_map(r: &entity_handler::HandlerResult) -> Vec<(Value, Value)> {
        let v: Value = ciborium::from_reader(r.result.data.as_slice()).unwrap();
        v.into_map().unwrap()
    }

    fn obs(key: &str, peer: Option<&str>) -> Observation {
        Observation {
            key: key.into(),
            peer_id: peer.map(|s| s.to_string()),
            endpoint_hint: text(key),
        }
    }

    #[tokio::test]
    async fn scan_writes_candidates_and_returns_snapshot() {
        let (cs, li) = stores();
        let backend = Arc::new(MockBackend {
            observations: vec![
                obs("svc-a", Some("z6MkPeerA")),
                obs("svc-b", None), // TOFU peer
            ],
        });
        let handler = DiscoveryHandler::new(cs.clone(), li.clone(), PEER.into(), vec![backend]);

        let res = handler.handle(&scan_ctx("mock")).await.unwrap();
        assert_eq!(res.status, entity_handler::STATUS_OK);

        let map = result_map(&res);
        let candidates = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("candidates"))
            .and_then(|(_, v)| v.as_array())
            .unwrap();
        assert_eq!(candidates.len(), 2, "two candidates surfaced");
        // truncated absent/false on an in-bound scan.
        let truncated = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("truncated"))
            .map(|(_, v)| matches!(v, Value::Bool(true)))
            .unwrap_or(false);
        assert!(!truncated);

        // The candidate entities were written into the tree under the watchable
        // prefix, and decode back to the observed peers.
        let entries = li.list(&candidate_prefix(PEER, "mock"));
        assert_eq!(entries.len(), 2, "both candidates in the tree");
        let mut peers: Vec<Option<String>> = entries
            .iter()
            .map(|e| {
                let h = li.get(&e.path).unwrap();
                let ent = cs.get(&h).unwrap();
                CandidateData::from_entity(&ent).unwrap().peer_id
            })
            .collect();
        peers.sort();
        assert_eq!(peers, vec![None, Some("z6MkPeerA".to_string())]);
    }

    #[tokio::test]
    async fn scan_over_ceiling_surfaces_overflow_not_silent() {
        let (cs, li) = stores();
        let backend = Arc::new(MockBackend {
            observations: (0..5).map(|i| obs(&format!("svc-{i}"), None)).collect(),
        });
        let handler = DiscoveryHandler::new(cs.clone(), li.clone(), PEER.into(), vec![backend])
            .with_scan_ceiling(3);

        let res = handler.handle(&scan_ctx("mock")).await.unwrap();
        let map = result_map(&res);

        let candidates = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("candidates"))
            .and_then(|(_, v)| v.as_array())
            .unwrap();
        assert_eq!(candidates.len(), 3, "truncated to ceiling");
        let truncated = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("truncated"))
            .map(|(_, v)| matches!(v, Value::Bool(true)))
            .unwrap_or(false);
        assert!(truncated, "§3.1/§8.4: overflow MUST surface");
        let code = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("code"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(code, Some(crate::CODE_SCAN_OVERFLOW));
    }

    #[tokio::test]
    async fn unsupported_backend_is_rejected_not_silent() {
        let (cs, li) = stores();
        let handler = DiscoveryHandler::new(cs, li, PEER.into(), vec![]);
        let res = handler.handle(&scan_ctx("mdns")).await.unwrap();
        assert_eq!(res.status, entity_handler::STATUS_BAD_REQUEST);
    }

    /// Live mDNS: one daemon announces, a second browses and finds it on the
    /// LAN. Requires a multicast-capable network (loopback multicast), so it is
    /// `#[ignore]`d in CI — run with `cargo test -p entity-discovery -- --ignored`
    /// on a real network to prove same-network discovery end-to-end.
    #[tokio::test]
    #[ignore = "requires a multicast-capable network"]
    async fn live_mdns_two_daemons_discover() {
        use crate::mdns::MdnsBackend;
        use std::time::Duration;

        let announcer = MdnsBackend::new();
        announcer
            .announce(&AnnounceParams {
                profile_ref: "tcp-default".into(),
                peer_id: Some("z6MkLivePeer".into()),
                proto: Some("tcp".into()),
                display_name: Some("live-test".into()),
                port: 47777,
            })
            .await
            .expect("announce");

        // Give the announcement time to propagate.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let browser = MdnsBackend::with_scan_window(Duration::from_secs(2));
        let found = browser.scan(None).await.expect("scan");

        assert!(
            found.iter().any(|o| o.peer_id.as_deref() == Some("z6MkLivePeer")),
            "browser must discover the announced peer; found: {found:?}"
        );

        announcer.announce_stop("tcp-default").await.expect("stop");
    }
}
