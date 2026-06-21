//! Integration tests for `SystemContentHandler` — exercise `get` +
//! `ingest` end-to-end against an in-memory content store and assert the
//! v3.5 `path_required` tightening.

use std::sync::Arc;

use ciborium::Value;
use entity_capability::ResourceTarget;
use entity_content::SystemContentHandler;
use entity_ecf::{cbor_map, text, ValueExt};
use entity_entity::Entity;
use entity_handler::{Handler, HandlerContext, HandlerResult, STATUS_BAD_REQUEST, STATUS_OK};
use entity_hash::Hash;
use entity_store::{ContentStore, MemoryContentStore};

const PEER_ID: &str = "test-peer";

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn make_handler() -> (SystemContentHandler, Arc<dyn ContentStore>) {
    let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    (SystemContentHandler::new(PEER_ID, store.clone()), store)
}

fn hash_record(h: &Hash) -> Value {
    // `system/hash` is a 33-byte CBOR bstr (algorithm || digest) per
    // ENTITY-NATIVE-TYPE-SYSTEM §4.5.
    Value::Bytes(h.to_bytes())
}

fn run(handler: &SystemContentHandler, op: &str, params: Entity, with_resource: bool) -> HandlerResult {
    let mut builder = HandlerContext::builder(params.clone(), params)
        .pattern(format!("/{}/system/content", PEER_ID))
        .operation(op)
        .request_id("test");
    if with_resource {
        builder = builder.resource_target(ResourceTarget {
            targets: vec!["system/content".to_string()],
            exclude: vec![],
        });
    }
    let ctx = builder.build();
    block_on(handler.handle(&ctx)).expect("handler did not error")
}

fn assert_error_kind(res: &HandlerResult, expected_status: u32, expected_code: &str) {
    assert_eq!(res.status, expected_status, "status mismatch");
    let v: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let got = v.get("code").and_then(|v| v.as_text()).unwrap_or("");
    assert_eq!(got, expected_code, "error code mismatch");
}

// --- get -------------------------------------------------------------

#[test]
fn get_without_resource_returns_path_required() {
    let (handler, _store) = make_handler();
    let params = Entity::new(
        "system/content/get-request",
        entity_ecf::to_ecf(&cbor_map! {
            "hashes" => Value::Array(vec![])
        }),
    )
    .unwrap();
    let res = run(&handler, "get", params, /*with_resource=*/ false);
    assert_error_kind(&res, STATUS_BAD_REQUEST, "path_required");
}

#[test]
fn get_returns_found_and_missing_partition() {
    let (handler, store) = make_handler();
    // Stage one entity in the store; ask for that plus one we never put.
    let stored = Entity::new(
        "system/peer",
        entity_ecf::to_ecf(&cbor_map! { "peer_id" => text("p") }),
    )
    .unwrap();
    let stored_hash = store.put(stored.clone()).unwrap();
    let missing_hash = Hash::new(0, [0xABu8; 32]);

    let params = Entity::new(
        "system/content/get-request",
        entity_ecf::to_ecf(&cbor_map! {
            "hashes" => Value::Array(vec![
                hash_record(&stored_hash),
                hash_record(&missing_hash),
            ])
        }),
    )
    .unwrap();
    let res = run(&handler, "get", params, /*with_resource=*/ true);
    assert_eq!(res.status, STATUS_OK);

    let v: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let found = v.get("found").and_then(|v| v.as_array().cloned()).unwrap();
    let missing = v.get("missing").and_then(|v| v.as_array().cloned()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(missing.len(), 1);

    // The stored entity was included in the response envelope.
    assert!(
        res.included.contains_key(&stored_hash),
        "found entity should ride in included"
    );
    assert!(
        !res.included.contains_key(&missing_hash),
        "missing entity should NOT ride in included"
    );
}

// --- ingest ----------------------------------------------------------

#[test]
fn ingest_without_resource_returns_path_required() {
    let (handler, _store) = make_handler();
    let params = Entity::new(
        "system/content/ingest-request",
        entity_ecf::to_ecf(&cbor_map! {
            "entity" => cbor_map! {
                "type" => text("system/peer"),
                "data" => cbor_map! { "peer_id" => text("p") }
            }
        }),
    )
    .unwrap();
    let res = run(&handler, "ingest", params, /*with_resource=*/ false);
    assert_error_kind(&res, STATUS_BAD_REQUEST, "path_required");
}

#[test]
fn ingest_entity_mode_stores_and_returns_hash() {
    let (handler, store) = make_handler();
    let params = Entity::new(
        "system/content/ingest-request",
        entity_ecf::to_ecf(&cbor_map! {
            "entity" => cbor_map! {
                "type" => text("system/peer"),
                "data" => cbor_map! { "peer_id" => text("p") }
            }
        }),
    )
    .unwrap();
    let res = run(&handler, "ingest", params, /*with_resource=*/ true);
    assert_eq!(res.status, STATUS_OK);

    let v: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let count = match v.get("ingested_count") {
        Some(Value::Integer(i)) => u64::try_from(*i).unwrap(),
        _ => panic!("missing ingested_count"),
    };
    assert_eq!(count, 1);
    // Entity mode: root MUST be absent (§6.3 spec).
    assert!(
        v.get("root").is_none(),
        "entity mode result must NOT inline root"
    );
    assert_eq!(store.len(), 1, "entity was stored");
}

#[test]
fn ingest_envelope_mode_inlines_root_and_validates_included_hashes() {
    let (handler, store) = make_handler();

    // The root we want to pass through.
    let root_data = cbor_map! { "peer_id" => text("root-peer") };
    let root_entity =
        Entity::new("system/peer", entity_ecf::to_ecf(&root_data)).unwrap();
    let root_hash = root_entity.content_hash.clone();

    // One extra included entity (hash-keyed map).
    let extra_data = cbor_map! { "peer_id" => text("extra-peer") };
    let extra_entity =
        Entity::new("system/peer", entity_ecf::to_ecf(&extra_data)).unwrap();
    let extra_hash = extra_entity.content_hash.clone();

    let included = Value::Map(vec![(
        hash_record(&extra_hash),
        cbor_map! {
            "type" => text("system/peer"),
            "data" => extra_data.clone()
        },
    )]);

    let params = Entity::new(
        "system/content/ingest-request",
        entity_ecf::to_ecf(&cbor_map! {
            "envelope" => cbor_map! {
                "root" => cbor_map! {
                    "type" => text("system/peer"),
                    "data" => root_data.clone()
                },
                "included" => included
            }
        }),
    )
    .unwrap();
    let res = run(&handler, "ingest", params, /*with_resource=*/ true);
    assert_eq!(res.status, STATUS_OK);

    let v: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let count = match v.get("ingested_count") {
        Some(Value::Integer(i)) => u64::try_from(*i).unwrap(),
        _ => panic!("missing ingested_count"),
    };
    assert_eq!(count, 2, "1 root + 1 included");
    // §11.1 MUST: envelope mode result inlines `root`.
    assert!(v.get("root").is_some(), "envelope mode must inline root");
    // Both entities are now retrievable from the content store.
    assert!(store.get(&root_hash).is_some());
    assert!(store.get(&extra_hash).is_some());
    let _ = root_entity;
    let _ = extra_entity;
}

#[test]
fn ingest_envelope_rejects_hash_mismatch_in_included() {
    let (handler, _store) = make_handler();

    // Build an included entry whose hash key is bogus.
    let entity_v = cbor_map! {
        "type" => text("system/peer"),
        "data" => cbor_map! { "peer_id" => text("x") }
    };
    let bogus_hash = Hash::new(0, [0xFFu8; 32]);
    let included = Value::Map(vec![(hash_record(&bogus_hash), entity_v)]);

    let params = Entity::new(
        "system/content/ingest-request",
        entity_ecf::to_ecf(&cbor_map! {
            "envelope" => cbor_map! {
                "included" => included
            }
        }),
    )
    .unwrap();
    let res = run(&handler, "ingest", params, /*with_resource=*/ true);
    assert_error_kind(&res, STATUS_BAD_REQUEST, "hash_mismatch");
}

#[test]
fn ingest_envelope_rejects_both_entity_and_envelope() {
    let (handler, _store) = make_handler();
    let params = Entity::new(
        "system/content/ingest-request",
        entity_ecf::to_ecf(&cbor_map! {
            "envelope" => cbor_map! {
                "root" => cbor_map! {
                    "type" => text("system/peer"),
                    "data" => cbor_map! {}
                }
            },
            "entity" => cbor_map! {
                "type" => text("system/peer"),
                "data" => cbor_map! {}
            }
        }),
    )
    .unwrap();
    let res = run(&handler, "ingest", params, /*with_resource=*/ true);
    assert_error_kind(&res, STATUS_BAD_REQUEST, "ambiguous_input");
}

// --- frame budget (CONTENT v3.6 §6.2 / §4.2 Amendment 1) -------------

#[test]
fn get_respects_configured_frame_budget() {
    // Stage 6 entities each ~1 KiB; configure a budget that fits 3 of
    // them comfortably. Spec contract: response carries `found` as a
    // strict in-request-order subset; the rest land in `missing`
    // regardless of local presence; requester retries with `missing`.
    let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let handler = SystemContentHandler::new(PEER_ID, store.clone())
        .with_frame_budget(4096);

    let payload = vec![0u8; 1024];
    let mut hashes: Vec<Hash> = Vec::with_capacity(6);
    for i in 0u8..6 {
        // Distinct entities — vary the type suffix so content-hashes differ.
        let ent = Entity::new(
            "system/peer",
            entity_ecf::to_ecf(&cbor_map! {
                "peer_id" => text(format!("p{}", i)),
                "filler" => Value::Bytes(payload.clone())
            }),
        )
        .unwrap();
        let h = store.put(ent).unwrap();
        hashes.push(h);
    }

    let request_hashes: Vec<Value> =
        hashes.iter().map(hash_record).collect();
    let params = Entity::new(
        "system/content/get-request",
        entity_ecf::to_ecf(&cbor_map! {
            "hashes" => Value::Array(request_hashes)
        }),
    )
    .unwrap();
    let res = run(&handler, "get", params, /*with_resource=*/ true);
    assert_eq!(res.status, STATUS_OK);

    let v: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let found = v
        .get("found")
        .and_then(|v| v.as_array().cloned())
        .unwrap();
    let missing = v
        .get("missing")
        .and_then(|v| v.as_array().cloned())
        .unwrap();

    // Strict subset — at least one included, at least one moved to missing.
    assert!(!found.is_empty(), "must include as many as fit");
    assert!(
        !missing.is_empty(),
        "must move overflow to missing even when locally present"
    );
    assert_eq!(
        found.len() + missing.len(),
        hashes.len(),
        "every requested hash accounted for exactly once"
    );

    // In-request-order: the `found` prefix matches the request prefix
    // (spec: "include as many as fit, in request order").
    for (i, h_in_found) in found.iter().enumerate() {
        let req_bstr = hash_record(&hashes[i]);
        assert_eq!(
            h_in_found.as_bytes(),
            req_bstr.as_bytes(),
            "found must be a prefix of the request in order"
        );
    }
}

#[test]
fn get_retry_with_missing_hashes_completes_closure() {
    // First call: tight budget partitions response. Second call asks
    // for the `missing` set with a budget that fits — every entity now
    // delivered; closure complete from the requester's POV.
    let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let handler = SystemContentHandler::new(PEER_ID, store.clone())
        .with_frame_budget(4096);

    let payload = vec![0u8; 1024];
    let mut hashes: Vec<Hash> = Vec::with_capacity(6);
    for i in 0u8..6 {
        let ent = Entity::new(
            "system/peer",
            entity_ecf::to_ecf(&cbor_map! {
                "peer_id" => text(format!("q{}", i)),
                "filler" => Value::Bytes(payload.clone())
            }),
        )
        .unwrap();
        hashes.push(store.put(ent).unwrap());
    }

    let req1: Vec<Value> = hashes.iter().map(hash_record).collect();
    let params1 = Entity::new(
        "system/content/get-request",
        entity_ecf::to_ecf(&cbor_map! { "hashes" => Value::Array(req1) }),
    )
    .unwrap();
    let res1 = run(&handler, "get", params1, true);
    assert_eq!(res1.status, STATUS_OK);
    let v1: Value = ciborium::from_reader(res1.result.data.as_slice()).unwrap();
    let missing1 = v1
        .get("missing")
        .and_then(|v| v.as_array().cloned())
        .unwrap();
    assert!(
        !missing1.is_empty(),
        "first call should partition (budget tight)"
    );

    // Retry with the missing-hash bstrs verbatim — same frame budget.
    // The smaller request fits within the budget; everything ships.
    let params2 = Entity::new(
        "system/content/get-request",
        entity_ecf::to_ecf(&cbor_map! { "hashes" => Value::Array(missing1.clone()) }),
    )
    .unwrap();
    let res2 = run(&handler, "get", params2, true);
    assert_eq!(res2.status, STATUS_OK);
    let v2: Value = ciborium::from_reader(res2.result.data.as_slice()).unwrap();
    let found2 = v2
        .get("found")
        .and_then(|v| v.as_array().cloned())
        .unwrap();
    let missing2 = v2
        .get("missing")
        .and_then(|v| v.as_array().cloned())
        .unwrap();
    assert_eq!(
        found2.len(),
        missing1.len(),
        "retry returns the requested set"
    );
    assert!(
        missing2.is_empty(),
        "no further partition needed for the retry-sized request"
    );
}
