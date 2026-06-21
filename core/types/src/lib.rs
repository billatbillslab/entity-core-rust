//! Type definitions and TypeRegistry.
//!
//! Entity types are validated against registered type definitions.
//! This crate also holds well-known type constants and core data structs.

pub mod core_types;
pub use core_types::register_core_types;

use std::collections::BTreeMap;
use std::sync::RwLock;

use entity_entity::Entity;
use entity_hash::Hash;
use sha2::{Digest, Sha256};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Well-known type constants
// ---------------------------------------------------------------------------

// Core
pub const TYPE_TYPE: &str = "system/type";

// Crypto
// PR-1 (PROPOSAL-SYSTEM-PEER-RENAME-AND-SUBSTRATE-CLEANUP, Rev 3): V7 entity
// type tag renamed `system/identity` → `system/peer`. The V7 entity holds
// `{peer_id, public_key, key_type}` — a peer IS its keypair entity. The
// EXTENSION-IDENTITY handler's `system/identity/...` paths are unaffected;
// only V7's bare `system/identity` (and `system/identity/peer-id`) rename.
pub const TYPE_PEER: &str = "system/peer";
pub const TYPE_PEER_SELF_STATUS: &str = "system/peer/self/status";
pub const TYPE_PUBLISHED_ROOT: &str = "system/peer/published-root";
/// EXTENSION-RELAY §3.5 — the MX-equivalent inbox-relay declaration: a signed,
/// self-certifying peer-fact declaring where to store-and-forward this peer's
/// mail when it is unreachable. Served always-on by REGISTRY (the DNS-zone
/// analog); resolves the §6.2.1 fallback rendezvous.
pub const TYPE_PEER_INBOX_RELAY: &str = "system/peer/inbox-relay";
pub const TYPE_SIGNATURE: &str = "system/signature";

// Handler
pub const TYPE_HANDLER: &str = "system/handler";
pub const TYPE_HANDLER_MANIFEST: &str = "system/handler/manifest";
pub const TYPE_HANDLER_REGISTER_REQ: &str = "system/handler/register-request";
pub const TYPE_HANDLER_REGISTER_RES: &str = "system/handler/register-result";
// TYPE_HANDLER_UNREGISTER_REQ removed: PROPOSAL-PATH-AS-RESOURCE-HYGIENE
// eliminated `system/handler/unregister-request`. Pattern is derived from
// the resource path; params is the empty-params shape (`primitive/any` `a0`).
pub const TYPE_HANDLER_INTERFACE: &str = "system/handler/interface";

// Capability
pub const TYPE_CAP_TOKEN: &str = "system/capability/token";
pub const TYPE_CAP_GRANT: &str = "system/capability/grant";
pub const TYPE_CAP_GRANT_ENTRY: &str = "system/capability/grant-entry";
pub const TYPE_CAP_DELEGATION: &str = "system/capability/delegation-caveats";
pub const TYPE_CAP_PATH_SCOPE: &str = "system/capability/path-scope";
pub const TYPE_CAP_ID_SCOPE: &str = "system/capability/id-scope";
pub const TYPE_CAP_REQUEST: &str = "system/capability/request";
pub const TYPE_CAP_REVOCATION: &str = "system/capability/revocation";
/// Multi-sig granter helper (PROPOSAL-MULTISIG-CORE-PRIMITIVE §M2).
pub const TYPE_CAP_MULTI_GRANTER: &str = "system/capability/multi-granter";
/// Input to `system/capability:revoke` (V7 §3.6, §6.2).
pub const TYPE_CAP_REVOKE_REQUEST: &str = "system/capability/revoke-request";
/// Input to `system/capability:delegate` (V7 §3.6, §6.2).
pub const TYPE_CAP_DELEGATE_REQUEST: &str = "system/capability/delegate-request";
/// Persisted policy entry written by `system/capability:configure`
/// (V7 §3.6, §6.2 baseline policy surface).
pub const TYPE_CAP_POLICY_ENTRY: &str = "system/capability/policy-entry";

// Tree
pub const TYPE_TREE_GET_REQ: &str = "system/tree/get-request";
pub const TYPE_TREE_PUT_REQ: &str = "system/tree/put-request";
pub const TYPE_TREE_PUT_RESULT: &str = "system/tree/put-result";
pub const TYPE_TREE_LISTING: &str = "system/tree/listing";
pub const TYPE_TREE_LISTING_ENTRY: &str = "system/tree/listing-entry";
pub const TYPE_TREE_PATH: &str = "system/tree/path";
pub const TYPE_TREE_SNAPSHOT: &str = "system/tree/snapshot";
pub const TYPE_TREE_SNAPSHOT_REQ: &str = "system/tree/snapshot-request";
pub const TYPE_TREE_DIFF: &str = "system/tree/diff";
pub const TYPE_TREE_DIFF_REQ: &str = "system/tree/diff-request";
pub const TYPE_TREE_DIFF_CHANGE: &str = "system/tree/diff/change";
pub const TYPE_TREE_MERGE_REQ: &str = "system/tree/merge-request";
pub const TYPE_TREE_MERGE_RESULT: &str = "system/tree/merge-result";
pub const TYPE_TREE_MERGE_CONFLICT: &str = "system/tree/merge-result/conflict";
pub const TYPE_TREE_EXTRACT_REQ: &str = "system/tree/extract-request";
pub const TYPE_TREE_TRACKING_CONFIG: &str = "system/tree/tracking-config";
pub const TYPE_TREE_PARTIAL_RESULT: &str = "system/tree/partial-result";

// Protocol
pub const TYPE_HELLO: &str = "system/protocol/connect/hello";
pub const TYPE_AUTHENTICATE: &str = "system/protocol/connect/authenticate";
pub const TYPE_EXECUTE: &str = "system/protocol/execute";
pub const TYPE_EXECUTE_RESPONSE: &str = "system/protocol/execute/response";
pub const TYPE_ERROR: &str = "system/protocol/error";
pub const TYPE_RESOURCE_TARGET: &str = "system/protocol/resource-target";

// Bounds
pub const TYPE_BOUNDS: &str = "system/bounds";

// Primitives
// PR-1: V7 type `system/identity/peer-id` → `system/peer-id`.
pub const TYPE_PEER_ID: &str = "system/peer-id";
pub const TYPE_TYPE_NAME: &str = "system/type/name";
pub const TYPE_HASH: &str = "system/hash";

// ENTITY-NATIVE-TYPE-SYSTEM v4.2.0 §4.9 — `system/deletion-marker` core
// type. Zero-field entity; canonical `data` is CBOR empty map (`0xa0`).
// Canonical hash: `ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6`.
// Consumed by EXTENSION-REVISION v3.1 for explicit-deletion semantics.
pub const TYPE_DELETION_MARKER: &str = "system/deletion-marker";

// Validate (EXTENSION-TYPE v1.1)
pub const TYPE_VALIDATE_REQ: &str = "system/type/validate-request";
pub const TYPE_VALIDATE_RES: &str = "system/type/validate-result";
pub const TYPE_VIOLATION: &str = "system/type/violation";

// EXTENSION-TYPE v1.1 — standard constraint types (§4) + envelope types (§5.2/§5.3)
pub const TYPE_CONSTRAINT_MIN: &str = "system/type/constraint/min";
pub const TYPE_CONSTRAINT_MAX: &str = "system/type/constraint/max";
pub const TYPE_CONSTRAINT_MIN_LENGTH: &str = "system/type/constraint/min-length";
pub const TYPE_CONSTRAINT_MAX_LENGTH: &str = "system/type/constraint/max-length";
pub const TYPE_CONSTRAINT_MIN_COUNT: &str = "system/type/constraint/min-count";
pub const TYPE_CONSTRAINT_MAX_COUNT: &str = "system/type/constraint/max-count";
pub const TYPE_CONSTRAINT_PATTERN: &str = "system/type/constraint/pattern";
pub const TYPE_CONSTRAINT_ONE_OF: &str = "system/type/constraint/one-of";
pub const TYPE_CONSTRAINT_NOT_ONE_OF: &str = "system/type/constraint/not-one-of";
pub const TYPE_CONSTRAINT_FORMAT: &str = "system/type/constraint/format";
pub const TYPE_CONSTRAINT_TYPE_PATTERN: &str = "system/type/constraint/type-pattern";
pub const TYPE_CONSTRAINT_VALIDATE_REQ: &str = "system/type/constraint/validate-request";
pub const TYPE_CONSTRAINT_VALIDATE_RES: &str = "system/type/constraint/validate-result";

// EXTENSION-TYPE v1.1 — analysis op support types (§8)
pub const TYPE_FIELD_COMPARISON: &str = "system/type/field-comparison";
pub const TYPE_FIELD_INCOMPATIBILITY: &str = "system/type/field-incompatibility";
pub const TYPE_COMPARE_REQ: &str = "system/type/compare-request";
pub const TYPE_COMPARE_RES: &str = "system/type/compare-result";
pub const TYPE_COMPATIBLE_REQ: &str = "system/type/compatible-request";
pub const TYPE_COMPATIBILITY_REPORT: &str = "system/type/compatibility-report";

// Delivery / subscription
pub const TYPE_DELIVERY_SPEC: &str = "system/delivery-spec";
pub const TYPE_INBOX_DELIVERY: &str = "system/protocol/inbox/delivery";

// Durability contract (EXTENSION-DURABILITY v0.1)
pub const TYPE_DURABILITY_REQUEST: &str = "system/durability-request";
pub const TYPE_DURABILITY_RESULT: &str = "system/durability-result";
pub const TYPE_SUBSCRIPTION: &str = "system/subscription";
pub const TYPE_SUBSCRIPTION_REQUEST: &str = "system/subscription/request";
pub const TYPE_SUBSCRIPTION_REDIRECT: &str = "system/subscription/redirect";
pub const TYPE_SUBSCRIPTION_CONFIG: &str = "system/config/subscription";

// Continuation
pub const TYPE_CONTINUATION: &str = "system/continuation";
pub const TYPE_CONTINUATION_JOIN: &str = "system/continuation/join";
// TYPE_CONTINUATION_INSTALL_REQUEST removed: PROPOSAL-PATH-AS-RESOURCE-HYGIENE
// (P-CONTINUATION-1) eliminated the wrapper. Caller passes
// system/continuation or system/continuation/join entity directly as params.
pub const TYPE_CONTINUATION_INSTALL_RESULT: &str = "system/continuation/install-result";

// Clock
pub const TYPE_CLOCK_TIMESTAMP: &str = "system/clock/timestamp";
pub const TYPE_CLOCK_LOGICAL: &str = "system/clock/logical";
pub const TYPE_CLOCK_VECTOR: &str = "system/clock/vector";
pub const TYPE_CLOCK_HLC: &str = "system/clock/hlc";
pub const TYPE_CLOCK_CONFIG: &str = "system/clock/config";
pub const TYPE_CLOCK_STATE: &str = "system/clock/state";
pub const TYPE_CLOCK_COMPARE_PARAMS: &str = "system/clock/compare-params";
pub const TYPE_CLOCK_COMPARE_RESULT: &str = "system/clock/compare-result";
pub const TYPE_CLOCK_TICK: &str = "system/clock/tick";

// Tree snapshot node (trie)
pub const TYPE_TREE_SNAPSHOT_NODE: &str = "system/tree/snapshot/node";

// Revision
pub const TYPE_REVISION_ENTRY: &str = "system/revision/entry";
pub const TYPE_REVISION_CONFLICT: &str = "system/revision/conflict";
pub const TYPE_REVISION_MERGE_CONFIG: &str = "system/revision/merge-config";
pub const TYPE_REVISION_CONFIG: &str = "system/revision/config";
pub const TYPE_REVISION_CONFIG_PARAMS: &str = "system/revision/config-params";
pub const TYPE_REVISION_CONFIG_RESULT: &str = "system/revision/config-result";
pub const TYPE_REVISION_CASCADE_WARNING: &str = "system/revision/cascade-warning";
pub const TYPE_REVISION_STATUS: &str = "system/revision/status";
pub const TYPE_REVISION_COMMIT_PARAMS: &str = "system/revision/commit-params";
pub const TYPE_REVISION_COMMIT_RESULT: &str = "system/revision/commit-result";
pub const TYPE_REVISION_LOG_PARAMS: &str = "system/revision/log-params";
pub const TYPE_REVISION_LOG_RESULT: &str = "system/revision/log-result";
pub const TYPE_REVISION_MERGE_PARAMS: &str = "system/revision/merge-params";
pub const TYPE_REVISION_MERGE_RESULT: &str = "system/revision/merge-result";
pub const TYPE_REVISION_MERGE_REQUEST: &str = "system/revision/merge-request";
pub const TYPE_REVISION_MERGE_RESPONSE: &str = "system/revision/merge-response";
pub const TYPE_REVISION_RESOLVE_PARAMS: &str = "system/revision/resolve-params";
pub const TYPE_REVISION_RESOLVE_RESULT: &str = "system/revision/resolve-result";
pub const TYPE_REVISION_FETCH_PARAMS: &str = "system/revision/fetch-params";
pub const TYPE_REVISION_FETCH_RESULT: &str = "system/revision/fetch-result";
pub const TYPE_REVISION_FETCH_ENTITIES_PARAMS: &str = "system/revision/fetch-entities-params";
pub const TYPE_REVISION_FETCH_ENTITIES_RESULT: &str = "system/revision/fetch-entities-result";
pub const TYPE_REVISION_PUSH_PARAMS: &str = "system/revision/push-params";
pub const TYPE_REVISION_PUSH_RESULT: &str = "system/revision/push-result";
pub const TYPE_REVISION_ANCESTOR_PARAMS: &str = "system/revision/ancestor-params";
pub const TYPE_REVISION_ANCESTOR_RESULT: &str = "system/revision/ancestor-result";
pub const TYPE_REVISION_STATUS_PARAMS: &str = "system/revision/status-params";
pub const TYPE_REVISION_BRANCH_PARAMS: &str = "system/revision/branch-params";
pub const TYPE_REVISION_BRANCH_RESULT: &str = "system/revision/branch-result";
pub const TYPE_REVISION_CHECKOUT_PARAMS: &str = "system/revision/checkout-params";
pub const TYPE_REVISION_CHECKOUT_RESULT: &str = "system/revision/checkout-result";
pub const TYPE_REVISION_TAG_PARAMS: &str = "system/revision/tag-params";
pub const TYPE_REVISION_TAG_RESULT: &str = "system/revision/tag-result";
pub const TYPE_REVISION_DIFF_PARAMS: &str = "system/revision/diff-params";
pub const TYPE_REVISION_CHERRY_PICK_PARAMS: &str = "system/revision/cherry-pick-params";
pub const TYPE_REVISION_CHERRY_PICK_RESULT: &str = "system/revision/cherry-pick-result";
pub const TYPE_REVISION_REVERT_PARAMS: &str = "system/revision/revert-params";
pub const TYPE_REVISION_REVERT_RESULT: &str = "system/revision/revert-result";

// Query
pub const TYPE_QUERY_EXPRESSION: &str = "system/query/expression";
pub const TYPE_QUERY_RESULT: &str = "system/query/result";
pub const TYPE_QUERY_MATCH: &str = "system/query/match";
pub const TYPE_QUERY_FIELD_PREDICATE: &str = "system/query/field-predicate";
pub const TYPE_QUERY_CONSTRAINTS: &str = "system/query/constraints";
pub const TYPE_QUERY_ALLOWANCES: &str = "system/query/allowances";
pub const TYPE_QUERY_INDEX_CONFIG: &str = "system/query/index-config";

// Attestation substrate (EXTENSION-ATTESTATION v1.1)
pub const TYPE_ATTESTATION: &str = "system/attestation";
pub const TYPE_ATTESTATION_CREATE_REQ: &str = "system/attestation/create-request";
pub const TYPE_ATTESTATION_CREATE_RES: &str = "system/attestation/create-result";
pub const TYPE_ATTESTATION_SUPERSEDE_REQ: &str = "system/attestation/supersede-request";
pub const TYPE_ATTESTATION_SUPERSEDE_RES: &str = "system/attestation/supersede-result";
pub const TYPE_ATTESTATION_REVOKE_REQ: &str = "system/attestation/revoke-request";
pub const TYPE_ATTESTATION_REVOKE_RES: &str = "system/attestation/revoke-result";
pub const TYPE_ATTESTATION_VERIFY_REQ: &str = "system/attestation/verify-request";
pub const TYPE_ATTESTATION_VERIFY_RES: &str = "system/attestation/verify-result";

// Quorum substrate (EXTENSION-QUORUM v1.1)
pub const TYPE_QUORUM: &str = "system/quorum";
pub const TYPE_QUORUM_CREATE_REQ: &str = "system/quorum/create-request";
pub const TYPE_QUORUM_CREATE_RES: &str = "system/quorum/create-result";
pub const TYPE_QUORUM_UPDATE_REQ: &str = "system/quorum/update-request";
pub const TYPE_QUORUM_UPDATE_RES: &str = "system/quorum/update-result";
pub const TYPE_QUORUM_PUBLISH_REQ: &str = "system/quorum/publish-request";
pub const TYPE_QUORUM_PUBLISH_RES: &str = "system/quorum/publish-result";
pub const TYPE_QUORUM_VERIFY_REQ: &str = "system/quorum/verify-request";
pub const TYPE_QUORUM_VERIFY_RES: &str = "system/quorum/verify-result";

// Identity (EXTENSION-IDENTITY v3.3 — substrate primitives moved out)
pub const TYPE_IDENTITY_PEER_CONFIG: &str = "system/identity/peer-config";
pub const TYPE_IDENTITY_IDENTITY_BINDING: &str = "system/identity/identity-binding";
pub const TYPE_IDENTITY_CONFIGURE_REQUEST: &str = "system/identity/configure-request";
pub const TYPE_IDENTITY_CONFIGURE_RESULT: &str = "system/identity/configure-result";
pub const TYPE_IDENTITY_CREATE_QUORUM_REQUEST: &str =
    "system/identity/create-quorum-request";
pub const TYPE_IDENTITY_CREATE_QUORUM_RESULT: &str = "system/identity/create-quorum-result";
pub const TYPE_IDENTITY_CREATE_ATTESTATION_REQUEST: &str =
    "system/identity/create-attestation-request";
pub const TYPE_IDENTITY_CREATE_ATTESTATION_RESULT: &str =
    "system/identity/create-attestation-result";
pub const TYPE_IDENTITY_SUPERSEDE_ATTESTATION_REQUEST: &str =
    "system/identity/supersede-attestation-request";
pub const TYPE_IDENTITY_SUPERSEDE_ATTESTATION_RESULT: &str =
    "system/identity/supersede-attestation-result";
pub const TYPE_IDENTITY_REVOKE_ATTESTATION_REQUEST: &str =
    "system/identity/revoke-attestation-request";
pub const TYPE_IDENTITY_REVOKE_ATTESTATION_RESULT: &str =
    "system/identity/revoke-attestation-result";
pub const TYPE_IDENTITY_PUBLISH_ATTESTATION_REQUEST: &str =
    "system/identity/publish-attestation-request";
pub const TYPE_IDENTITY_PUBLISH_ATTESTATION_RESULT: &str =
    "system/identity/publish-attestation-result";
/// PI-5 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-5, Rev 3):
/// controller-events stream entity. Emitted on phase-2 handler failures
/// in `:process_attestation` and on orphan-binding recoveries in
/// `:publish_attestation` (PI-3). Carries `event_subkind` discriminator:
/// `"recovery_signal"` (retention-protected; MUST NOT be pruned until
/// cleared) or `"failure_observation"` (impl-defined retention).
pub const TYPE_IDENTITY_EVENT: &str = "system/identity/event";
pub const TYPE_PROTOCOL_STATUS: &str = "system/protocol/status";

// Role extension (EXTENSION-ROLE v1.6)
pub const TYPE_ROLE: &str = "system/role";
pub const TYPE_ROLE_ASSIGNMENT: &str = "system/role/assignment";
pub const TYPE_ROLE_EXCLUSION: &str = "system/role/exclusion";
/// SI-5: linkage entity at sibling subtree
/// `system/role/{context}/derived-tokens/{peer_id_hex}/{role_name}`.
pub const TYPE_ROLE_DERIVED_TOKEN_LINK: &str = "system/role/derived-token-link";
pub const TYPE_ROLE_DEFINE_REQUEST: &str = "system/role/define-request";
pub const TYPE_ROLE_DEFINE_RESULT: &str = "system/role/define-result";
pub const TYPE_ROLE_ASSIGN_REQUEST: &str = "system/role/assign-request";
pub const TYPE_ROLE_ASSIGN_RESULT: &str = "system/role/assign-result";
pub const TYPE_ROLE_UNASSIGN_RESULT: &str = "system/role/unassign-result";
pub const TYPE_ROLE_EXCLUDE_RESULT: &str = "system/role/exclude-result";
pub const TYPE_ROLE_UNEXCLUDE_RESULT: &str = "system/role/unexclude-result";
pub const TYPE_ROLE_RE_DERIVE_REQUEST: &str = "system/role/re-derive-request";
pub const TYPE_ROLE_RE_DERIVE_RESULT: &str = "system/role/re-derive-result";
pub const TYPE_ROLE_DELEGATE_REQUEST: &str = "system/role/delegate-request";
pub const TYPE_ROLE_DELEGATE_RESULT: &str = "system/role/delegate-result";
/// Initial-grant policy entity (EXTENSION-ROLE §4.7). Singleton at
/// `system/role/initial-grant-policy`. Drives the connect-handler's
/// grant-resolver dispatch (deny / allow / recognize-on-attestation).
pub const TYPE_ROLE_INITIAL_GRANT_POLICY: &str = "system/role/initial-grant-policy";

// Registry (EXTENSION-REGISTRY v1.0) — substrate + local-name backend
pub const TYPE_REGISTRY_BINDING: &str = "system/registry/binding";
pub const TYPE_REGISTRY_REVOCATION: &str = "system/registry/revocation";
pub const TYPE_REGISTRY_RESOLVER_CONFIG: &str = "system/registry/resolver-config";
pub const TYPE_REGISTRY_LOCAL_NAME_CONFIG: &str = "system/registry/local-name-config";
pub const TYPE_REGISTRY_RESOLUTION_LOG: &str = "system/registry/resolution-log";
// Peer-issued live registration (EXTENSION-REGISTRY §6a.9).
pub const TYPE_REGISTRY_REGISTER_REQUEST: &str = "system/registry/register-request";
pub const TYPE_REGISTRY_ISSUER_POLICY: &str = "system/registry/issuer-policy";

// Discovery (EXTENSION-DISCOVERY v1.0) — find-and-prompt substrate
// §2.1 candidate/decision entity types; §2.2.1 identity-claim.
pub const TYPE_DISCOVERY_CANDIDATE: &str = "system/discovery/candidate";
pub const TYPE_DISCOVERY_DECISION: &str = "system/discovery/decision";
pub const TYPE_DISCOVERY_IDENTITY_CLAIM: &str = "system/discovery/identity-claim";

// Relay (EXTENSION-RELAY v1.0) — opaque-envelope transport substrate.
// §3.1 forward-request (Mode F); §3.2 store-entry (Mode S); §4.1 advertise.
// Flat result types are pinned slugs (handoff §3): no system/protocol/status wrap.
pub const TYPE_RELAY_FORWARD_REQUEST: &str = "system/relay/forward-request";
pub const TYPE_RELAY_STORE_ENTRY: &str = "system/relay/store-entry";
pub const TYPE_RELAY_ADVERTISE: &str = "system/relay/advertise";
pub const TYPE_RELAY_FORWARD_RESULT: &str = "system/relay/forward-result";
pub const TYPE_RELAY_PUT_RESULT: &str = "system/relay/put-result";
pub const TYPE_RELAY_POLL_REQUEST: &str = "system/relay/poll-request";
pub const TYPE_RELAY_POLL_RESULT: &str = "system/relay/poll-result";

// History
pub const TYPE_HISTORY_TRANSITION: &str = "system/history/transition";
pub const TYPE_HISTORY_CONFIG: &str = "system/history/config";
pub const TYPE_HISTORY_QUERY_PARAMS: &str = "system/history/query-params";
pub const TYPE_HISTORY_QUERY_RESULT: &str = "system/history/query-result";
pub const TYPE_HISTORY_ROLLBACK_PARAMS: &str = "system/history/rollback-params";
pub const TYPE_HISTORY_ROLLBACK_RESULT: &str = "system/history/rollback-result";

// Envelope
pub const TYPE_ENVELOPE: &str = "system/envelope";

// Bootstrap entity types (TYPE-SYSTEM §2.7.1, §3.1.1, §8.1;
// PROPOSAL-TYPE-NAMESPACE-CONVENTIONS).
//
// `entity` (bare): the abstract structural root `{type, data}`. Every entity
// type structurally specializes this. content_hash is *derived*, not declared.
//
// `core/entity`: the materialized form `{type, data, content_hash}`. Used as a
// `type_ref` marker in field specs to require "this slot holds a real,
// identity-bearing entity, not raw CBOR." Lives in `core/*` alongside
// `core/envelope`.
pub const TYPE_ENTITY: &str = "entity";
pub const TYPE_CORE_ENTITY: &str = "core/entity";

// Content (EXTENSION-CONTENT v3.5)
pub const TYPE_CONTENT_BLOB: &str = "system/content/blob";
pub const TYPE_CONTENT_CHUNK: &str = "system/content/chunk";
pub const TYPE_CONTENT_DESCRIPTOR: &str = "system/content/descriptor";
pub const TYPE_CONTENT_GET_REQUEST: &str = "system/content/get-request";
pub const TYPE_CONTENT_CONTENT_RESPONSE: &str = "system/content/content-response";
pub const TYPE_CONTENT_INGEST_REQUEST: &str = "system/content/ingest-request";
pub const TYPE_CONTENT_INGEST_RESULT: &str = "system/content/ingest-result";

/// `system/content/blob`'s `chunking` field — fixed-size algorithm (§2.1).
pub const CONTENT_CHUNKING_FIXED: u64 = 0;
/// `system/content/blob`'s `chunking` field — FastCDC/NC2 algorithm (§2.1).
pub const CONTENT_CHUNKING_FASTCDC: u64 = 1;

/// EXTENSION-CONTENT v3.6 §3.5 `DEFAULT_CHUNK_SIZE` (1 MiB).
///
/// A2 cutover: shifted from 4 MiB → 1 MiB per v3.6 §3.5.
/// Matches the centroid of production CDC systems (Borg, restic,
/// casync). Existing 4 MiB chunks remain valid (chunk_size is recorded
/// per-blob); cross-peer dedup is preserved per `same chunk_size`
/// equivalence class. The §5.5 circuit-breaker fix (uses incoming
/// blob's chunk_size, not local default) makes mixed-version
/// deployments safe — peers running this 1 MiB default exchange
/// content with peers still on 4 MiB without spurious rewrites.
pub const CONTENT_DEFAULT_CHUNK_SIZE: u64 = 1 * 1024 * 1024;
/// EXTENSION-CONTENT §10.1 `MIN_CHUNK_SIZE` (64 KiB). Also the §4.3
/// inline-include threshold.
pub const CONTENT_MIN_CHUNK_SIZE: u64 = 64 * 1024;
/// EXTENSION-CONTENT §10.1 `MAX_CHUNK_SIZE` (8 MiB).
pub const CONTENT_MAX_CHUNK_SIZE: u64 = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// TypeDefinition + FieldSpec
// ---------------------------------------------------------------------------

/// A type definition: describes the shape of an entity's data.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeDefinition {
    /// Type name (e.g., "system/handler").
    pub name: String,
    /// Parent type this extends (if any).
    pub extends: Option<String>,
    /// Field specifications keyed by field name.
    pub fields: BTreeMap<String, FieldSpec>,
    /// Ordered field layout (for canonical serialization).
    pub layout: Vec<String>,
    /// Type parameters (for generic types).
    pub type_params: Vec<String>,
    /// Type arguments (for instantiated generic types).
    pub type_args: BTreeMap<String, String>,
}

impl TypeDefinition {
    /// Create a minimal type definition with just a name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            extends: None,
            fields: BTreeMap::new(),
            layout: Vec::new(),
            type_params: Vec::new(),
            type_args: BTreeMap::new(),
        }
    }

    /// Create a type definition with fields.
    pub fn with_fields(name: &str, fields: BTreeMap<String, FieldSpec>) -> Self {
        Self {
            name: name.to_string(),
            extends: None,
            fields,
            layout: Vec::new(),
            type_params: Vec::new(),
            type_args: BTreeMap::new(),
        }
    }

    /// ECF-encode this definition and wrap it as a `system/type` entity.
    pub fn to_entity(&self) -> Result<Entity, TypesError> {
        let mut map_entries = vec![(
            entity_ecf::text("name"),
            entity_ecf::text(&self.name),
        )];

        if let Some(ref extends) = self.extends {
            map_entries.push((entity_ecf::text("extends"), entity_ecf::text(extends)));
        }

        if !self.fields.is_empty() {
            let field_entries: Vec<(entity_ecf::Value, entity_ecf::Value)> = self
                .fields
                .iter()
                .map(|(k, v)| (entity_ecf::text(k), v.to_value()))
                .collect();
            map_entries.push((
                entity_ecf::text("fields"),
                entity_ecf::Value::Map(field_entries),
            ));
        }

        if !self.layout.is_empty() {
            let arr: Vec<entity_ecf::Value> =
                self.layout.iter().map(entity_ecf::text).collect();
            map_entries.push((entity_ecf::text("layout"), entity_ecf::array(arr)));
        }

        let value = entity_ecf::Value::Map(map_entries);
        let data = entity_ecf::to_ecf(&value);
        Entity::new(TYPE_TYPE, data).map_err(|e| TypesError::EntityError(e.to_string()))
    }

    /// The tree path where this type definition would be stored.
    pub fn tree_path(&self) -> String {
        format!("system/type/{}", self.name)
    }
}

/// A constraint attached to a field-spec (EXTENSION-TYPE v1.1 §3).
///
/// Each constraint is an entity `{type, data}` whose type determines the
/// dispatch handler (`system/type/constraint/{kind}` for standards) and
/// whose data carries the constraint parameters. When embedded inside a
/// type definition's `constraints` field, the constraint serializes in
/// the `core/entity` shape: `{content_hash, data, type}` per §3.3.
#[derive(Debug, Clone)]
pub struct ConstraintRef {
    /// Constraint type path (e.g., "system/type/constraint/min").
    pub constraint_type: String,
    /// Constraint parameter map (e.g., `{"min": 0}`). Inline CBOR — when
    /// serialized as part of the surrounding type entity's `data`, this
    /// value is ECF-encoded and embedded directly under the `data` key.
    pub data: entity_ecf::Value,
}

impl ConstraintRef {
    pub fn new(constraint_type: &str, data: entity_ecf::Value) -> Self {
        Self {
            constraint_type: constraint_type.to_string(),
            data,
        }
    }

    /// Content hash of the constraint entity. Hashes `{type, data}` per
    /// V7 §7 — `data` is ECF-encoded first.
    pub fn content_hash(&self) -> Hash {
        let data_bytes = entity_ecf::to_ecf(&self.data);
        Hash::compute(&self.constraint_type, &data_bytes)
    }

    /// Materialize as an `Entity` for dispatch.
    pub fn to_entity(&self) -> Result<Entity, TypesError> {
        let data_bytes = entity_ecf::to_ecf(&self.data);
        Entity::new(&self.constraint_type, data_bytes)
            .map_err(|e| TypesError::EntityError(e.to_string()))
    }

    /// CBOR map value for embedding inside a FieldSpec's encoded map.
    /// Shape: `{content_hash: bstr, data: <inline>, type: text}` —
    /// ECF-sorted keys (encoded length, then lex).
    fn to_value(&self) -> entity_ecf::Value {
        let hash = self.content_hash();
        entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("data"),
                self.data.clone(),
            ),
            (
                entity_ecf::text("type"),
                entity_ecf::text(&self.constraint_type),
            ),
            (
                entity_ecf::text("content_hash"),
                entity_ecf::Value::Bytes(hash.to_bytes().to_vec()),
            ),
        ])
    }
}

impl PartialEq for ConstraintRef {
    fn eq(&self, other: &Self) -> bool {
        if self.constraint_type != other.constraint_type {
            return false;
        }
        entity_ecf::to_ecf(&self.data) == entity_ecf::to_ecf(&other.data)
    }
}

/// Specification for a single field in a type definition.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldSpec {
    /// Reference to another type (e.g., "primitive/string").
    pub type_ref: Option<String>,
    /// Whether this field is optional.
    pub optional: bool,
    /// If this field is an array, the element spec.
    pub array_of: Option<Box<FieldSpec>>,
    /// If this field is a map, the value spec.
    pub map_of: Option<Box<FieldSpec>>,
    /// If this field is a union, the variant specs.
    pub union_of: Vec<FieldSpec>,
    /// Key type for map fields.
    pub key_type: Option<String>,
    /// Fixed byte width (for structured primitive layouts).
    pub byte_size: Option<u64>,
    /// Constraints attached to this field (EXTENSION-TYPE v1.1 §3).
    /// Conjunctive — all must pass. Absent (empty) means unconstrained.
    pub constraints: Vec<ConstraintRef>,
}

impl FieldSpec {
    /// Create a field spec referencing a type.
    pub fn type_ref(name: &str) -> Self {
        Self {
            type_ref: Some(name.to_string()),
            optional: false,
            array_of: None,
            map_of: None,
            union_of: Vec::new(),
            key_type: None,
            byte_size: None,
            constraints: Vec::new(),
        }
    }

    /// Create an optional field spec.
    pub fn optional(name: &str) -> Self {
        Self {
            type_ref: Some(name.to_string()),
            optional: true,
            array_of: None,
            map_of: None,
            union_of: Vec::new(),
            key_type: None,
            byte_size: None,
            constraints: Vec::new(),
        }
    }

    /// Create a type reference with a fixed byte size (for structured primitives).
    pub fn type_ref_with_byte_size(name: &str, size: u64) -> Self {
        Self {
            type_ref: Some(name.to_string()),
            optional: false,
            array_of: None,
            map_of: None,
            union_of: Vec::new(),
            key_type: None,
            byte_size: Some(size),
            constraints: Vec::new(),
        }
    }

    /// Create an array field spec.
    pub fn array(element: FieldSpec) -> Self {
        Self {
            type_ref: None,
            optional: false,
            array_of: Some(Box::new(element)),
            map_of: None,
            union_of: Vec::new(),
            key_type: None,
            byte_size: None,
            constraints: Vec::new(),
        }
    }

    /// Create an optional array field spec.
    pub fn optional_array(element: FieldSpec) -> Self {
        Self {
            type_ref: None,
            optional: true,
            array_of: Some(Box::new(element)),
            map_of: None,
            union_of: Vec::new(),
            key_type: None,
            byte_size: None,
            constraints: Vec::new(),
        }
    }

    /// Create a map field spec.
    pub fn map(value: FieldSpec, key_type: Option<&str>) -> Self {
        Self {
            type_ref: None,
            optional: false,
            array_of: None,
            map_of: Some(Box::new(value)),
            union_of: Vec::new(),
            key_type: key_type.map(|s| s.to_string()),
            byte_size: None,
            constraints: Vec::new(),
        }
    }

    /// Create an optional map field spec.
    pub fn optional_map(value: FieldSpec, key_type: Option<&str>) -> Self {
        Self {
            type_ref: None,
            optional: true,
            array_of: None,
            map_of: Some(Box::new(value)),
            union_of: Vec::new(),
            key_type: key_type.map(|s| s.to_string()),
            byte_size: None,
            constraints: Vec::new(),
        }
    }

    /// Create a union field spec — a value matches one of the variants
    /// (per ENTITY-NATIVE-TYPE-SYSTEM §4.2 `union_of`). When variants
    /// have distinct CBOR major types (e.g., `system/hash` is bstr vs
    /// `system/capability/multi-granter` is map), implementations
    /// dispatch on encoded major type per §7.3.1.
    pub fn union(variants: Vec<FieldSpec>) -> Self {
        Self {
            type_ref: None,
            optional: false,
            array_of: None,
            map_of: None,
            union_of: variants,
            key_type: None,
            byte_size: None,
            constraints: Vec::new(),
        }
    }

    /// Builder-style: attach a constraint to this field-spec. Constraints
    /// are conjunctive per EXTENSION-TYPE v1.1 §3.2.
    pub fn with_constraint(mut self, c: ConstraintRef) -> Self {
        self.constraints.push(c);
        self
    }

    /// Builder-style: attach multiple constraints.
    pub fn with_constraints(mut self, mut cs: Vec<ConstraintRef>) -> Self {
        self.constraints.append(&mut cs);
        self
    }

    /// Convert to a ciborium Value for ECF encoding.
    ///
    /// Insertion order is irrelevant — `entity_ecf::to_ecf` re-sorts map
    /// keys by ECF rules (encoded byte length, then lex). Alphabetical
    /// insertion is purely for source readability.
    pub fn to_value(&self) -> entity_ecf::Value {
        let mut entries = Vec::new();

        if let Some(ref ao) = self.array_of {
            entries.push((entity_ecf::text("array_of"), ao.to_value()));
        }
        if let Some(bs) = self.byte_size {
            entries.push((
                entity_ecf::text("byte_size"),
                entity_ecf::integer(bs as i64),
            ));
        }
        if !self.constraints.is_empty() {
            let arr: Vec<entity_ecf::Value> =
                self.constraints.iter().map(|c| c.to_value()).collect();
            entries.push((entity_ecf::text("constraints"), entity_ecf::array(arr)));
        }
        if let Some(ref kt) = self.key_type {
            entries.push((entity_ecf::text("key_type"), entity_ecf::text(kt)));
        }
        if let Some(ref mo) = self.map_of {
            entries.push((entity_ecf::text("map_of"), mo.to_value()));
        }
        if self.optional {
            entries.push((
                entity_ecf::text("optional"),
                entity_ecf::bool_val(true),
            ));
        }
        if let Some(ref tr) = self.type_ref {
            entries.push((entity_ecf::text("type_ref"), entity_ecf::text(tr)));
        }
        // CROSS-IMPL-RUST: union_of MUST be serialized; pre-fix
        // Rust dropped it on encode, so `system/capability/token.granter`
        // published an empty FieldSpec — Go's validator flagged a hash
        // mismatch because Go's local def had `union_of(system/hash,
        // system/capability/multi-granter)` (per PROPOSAL-MULTISIG-CORE
        // §M3) but Rust's published def carried no field metadata at all.
        if !self.union_of.is_empty() {
            let arr: Vec<entity_ecf::Value> =
                self.union_of.iter().map(|fs| fs.to_value()).collect();
            entries.push((entity_ecf::text("union_of"), entity_ecf::array(arr)));
        }

        entity_ecf::Value::Map(entries)
    }
}

// ---------------------------------------------------------------------------
// TypeDefBuilder
// ---------------------------------------------------------------------------

/// Builder for creating type definitions with fields using method chaining.
pub struct TypeDefBuilder {
    name: String,
    extends: Option<String>,
    fields: BTreeMap<String, FieldSpec>,
    layout: Option<Vec<String>>,
}

impl TypeDefBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            extends: None,
            fields: BTreeMap::new(),
            layout: None,
        }
    }

    pub fn extends(mut self, parent: &str) -> Self {
        self.extends = Some(parent.to_string());
        self
    }

    pub fn field(mut self, name: &str, spec: FieldSpec) -> Self {
        self.fields.insert(name.to_string(), spec);
        self
    }

    pub fn layout(mut self, order: Vec<&str>) -> Self {
        self.layout = Some(order.into_iter().map(String::from).collect());
        self
    }

    pub fn build(self) -> TypeDefinition {
        let layout = self.layout.unwrap_or_default();
        TypeDefinition {
            name: self.name,
            extends: self.extends,
            fields: self.fields,
            layout,
            type_params: Vec::new(),
            type_args: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Core data structs
// ---------------------------------------------------------------------------

/// Data payload for `system/peer` entities — V7 §3.5 v7.65.
///
/// `peer_id` exits the hashable basis (Amendment 1+2 — P×I primitive
/// discipline). `content_hash(system/peer)` is a pure function of
/// `(public_key, key_type)` and is invariant under wire-form `peer_id`
/// choice. Wire `peer_id`s are derived at the wire layer from
/// `(public_key, key_type)` + canonical `hash_type` per §1.5; they do
/// NOT contribute to the entity's content_hash.
///
/// Composition with v7.64: legacy entities carrying a `peer_id` map key
/// still decode cleanly via [`PeerData::from_entity`] (the field is
/// silently ignored). Their content_hashes remain valid; cap chains
/// referencing them stay verifiable byte-for-byte. New entities minted
/// after v7.65 use this shape.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerData {
    pub public_key: Vec<u8>,
    pub key_type: String,
}

impl PeerData {
    /// Decode from an entity's raw CBOR data. Tolerates v7.64-shape input
    /// (an unknown `peer_id` key on a legacy entity is silently dropped —
    /// the field exits the schema under v7.65 but pre-v7.65 entities are
    /// still decodable for chain-verification continuity).
    pub fn from_entity(entity: &Entity) -> Result<Self, TypesError> {
        if entity.entity_type != TYPE_PEER {
            return Err(TypesError::WrongType {
                expected: TYPE_PEER.into(),
                actual: entity.entity_type.clone(),
            });
        }
        let value: ciborium::Value =
            ciborium::from_reader(entity.data.as_slice())
                .map_err(|e| TypesError::DecodeError(e.to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| TypesError::DecodeError("expected CBOR map".into()))?;

        let mut public_key = None;
        let mut key_type = None;

        for (k, v) in map {
            match k.as_text() {
                Some("public_key") => public_key = v.as_bytes().map(|b| b.to_vec()),
                Some("key_type") => key_type = v.as_text().map(|s| s.to_string()),
                _ => {}
            }
        }

        Ok(Self {
            public_key: public_key
                .ok_or_else(|| TypesError::DecodeError("missing public_key".into()))?,
            key_type: key_type
                .ok_or_else(|| TypesError::DecodeError("missing key_type".into()))?,
        })
    }

    /// Encode to an entity — V7 §3.5 v7.65 canonical shape.
    pub fn to_entity(&self) -> Result<Entity, TypesError> {
        let value = entity_ecf::Value::Map(vec![
            (entity_ecf::text("key_type"), entity_ecf::text(&self.key_type)),
            (
                entity_ecf::text("public_key"),
                entity_ecf::Value::Bytes(self.public_key.clone()),
            ),
        ]);
        let data = entity_ecf::to_ecf(&value);
        Entity::new(TYPE_PEER, data).map_err(|e| TypesError::EntityError(e.to_string()))
    }

    /// Derive the canonical wire `peer_id` (Base58) for this peer per V7
    /// §1.5 v7.65 / §3.2 v7.67. Ed25519's canonical form is
    /// identity-multihash (`hash_type=0x00`, digest = raw public_key);
    /// Ed448's is SHA-256-form (`hash_type=0x01`, digest =
    /// SHA-256(public_key)), forced because its 57-byte key exceeds the
    /// identity-multihash size floor. Returns `None` for unknown
    /// `key_type` strings or `public_key` byte lengths that don't match
    /// the algorithm.
    ///
    /// The bytes — `varint(key_type) || varint(hash_type) || digest` —
    /// are assembled by hand (not via entity_crypto) to keep core/types
    /// below crypto in the DAG. `key_type`/`hash_type` are all `< 0x80`,
    /// so each is a single LEB128 byte, matching crypto's `encode_raw`.
    pub fn canonical_peer_id(&self) -> Option<String> {
        // (key_type byte, canonical hash_type byte, expected public_key len)
        let (key_type_byte, hash_type_byte, pubkey_len) = match self.key_type.as_str() {
            "ed25519" => (0x01u8, 0x00u8, 32usize),
            "ed448" => (0x02u8, 0x01u8, 57usize),
            _ => return None,
        };
        if self.public_key.len() != pubkey_len {
            return None;
        }
        // hash_type 0x00 embeds the raw key; 0x01 hashes it with SHA-256.
        let digest: Vec<u8> = if hash_type_byte == 0x00 {
            self.public_key.clone()
        } else {
            Sha256::digest(&self.public_key).to_vec()
        };
        let mut raw = Vec::with_capacity(2 + digest.len());
        raw.push(key_type_byte);
        raw.push(hash_type_byte);
        raw.extend_from_slice(&digest);
        Some(bs58::encode(raw).into_string())
    }
}

/// Data payload for `system/signature` entities.
#[derive(Debug, Clone, PartialEq)]
pub struct SignatureData {
    /// Content hash of the signed entity.
    pub target: Hash,
    /// Content hash of the signer's identity entity (NOT peer_id string).
    pub signer: Hash,
    /// Signature algorithm (e.g., "ed25519").
    pub algorithm: String,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

impl SignatureData {
    /// Decode from an entity's raw CBOR data.
    pub fn from_entity(entity: &Entity) -> Result<Self, TypesError> {
        if entity.entity_type != TYPE_SIGNATURE {
            return Err(TypesError::WrongType {
                expected: TYPE_SIGNATURE.into(),
                actual: entity.entity_type.clone(),
            });
        }
        let value: ciborium::Value =
            ciborium::from_reader(entity.data.as_slice())
                .map_err(|e| TypesError::DecodeError(e.to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| TypesError::DecodeError("expected CBOR map".into()))?;

        let mut target = None;
        let mut signer = None;
        let mut algorithm = None;
        let mut signature = None;

        for (k, v) in map {
            match k.as_text() {
                Some("target") => {
                    if let Some(b) = v.as_bytes() {
                        target = Some(
                            Hash::from_bytes(b)
                                .map_err(|e| TypesError::DecodeError(e.to_string()))?,
                        );
                    }
                }
                Some("signer") => {
                    if let Some(b) = v.as_bytes() {
                        signer = Some(
                            Hash::from_bytes(b)
                                .map_err(|e| TypesError::DecodeError(e.to_string()))?,
                        );
                    }
                }
                Some("algorithm") => algorithm = v.as_text().map(|s| s.to_string()),
                Some("signature") => signature = v.as_bytes().map(|b| b.to_vec()),
                _ => {}
            }
        }

        Ok(Self {
            target: target
                .ok_or_else(|| TypesError::DecodeError("missing target".into()))?,
            signer: signer
                .ok_or_else(|| TypesError::DecodeError("missing signer".into()))?,
            algorithm: algorithm
                .ok_or_else(|| TypesError::DecodeError("missing algorithm".into()))?,
            signature: signature
                .ok_or_else(|| TypesError::DecodeError("missing signature".into()))?,
        })
    }

    /// Encode to an entity.
    pub fn to_entity(&self) -> Result<Entity, TypesError> {
        let value = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("algorithm"),
                entity_ecf::text(&self.algorithm),
            ),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(self.signature.clone()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(self.signer.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(self.target.to_bytes().to_vec()),
            ),
        ]);
        let data = entity_ecf::to_ecf(&value);
        Entity::new(TYPE_SIGNATURE, data).map_err(|e| TypesError::EntityError(e.to_string()))
    }
}

/// Data payload for `system/peer/published-root` entities
/// (PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4, NORMATIVE-LOCKED).
///
/// The signed, fetchable anchor for a peer's current tree root. `TREE_GET` over
/// an untrusted intermediary MUST walk the hash-chain from this signed
/// `root_hash` (§1.1 threat model) rather than trusting host-served path
/// bindings. The authenticating `system/signature` is carried per the
/// invariant-pointer contract at `system/signature/{hex(content_hash)}`, NOT
/// inline in a `refs:` block.
///
/// **`peer_id` wire shape.** Carried as a Base58 peer-id string (V7 §1.5
/// multikey), matching the sibling `system/peer/transport/http-poll.peer_id`
/// (NETWORK errata `bdfb545`) and the Go coordinator's P1 build target. The
/// locked §4 text writes `<hash>`; see `docs/SPEC-AMBIGUITIES.md` for the
/// divergence note. `root_hash` / `predecessor` are bare `system/hash` (33
/// bytes, `0x00`+digest); `predecessor` is absent (key not present) when null.
#[derive(Debug, Clone, PartialEq)]
pub struct PublishedRootData {
    /// Base58 peer-id whose root this is.
    pub peer_id: String,
    /// The current tree root the publisher commits to (bare `system/hash`).
    pub root_hash: Hash,
    /// Monotonic freshness counter (reject `seq < cached` on receive).
    pub seq: u64,
    /// Publication timestamp, milliseconds since Unix epoch.
    pub published_at: u64,
    /// The previous published-root, forming an audit chain (bare `system/hash`).
    pub predecessor: Option<Hash>,
}

impl PublishedRootData {
    /// Decode from an entity's raw CBOR data.
    pub fn from_entity(entity: &Entity) -> Result<Self, TypesError> {
        if entity.entity_type != TYPE_PUBLISHED_ROOT {
            return Err(TypesError::WrongType {
                expected: TYPE_PUBLISHED_ROOT.into(),
                actual: entity.entity_type.clone(),
            });
        }
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| TypesError::DecodeError(e.to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| TypesError::DecodeError("expected CBOR map".into()))?;

        let mut peer_id = None;
        let mut root_hash = None;
        let mut seq = None;
        let mut published_at = None;
        let mut predecessor = None;

        for (k, v) in map {
            match k.as_text() {
                Some("peer_id") => peer_id = v.as_text().map(|s| s.to_string()),
                Some("root_hash") => {
                    if let Some(b) = v.as_bytes() {
                        root_hash = Some(
                            Hash::from_bytes(b)
                                .map_err(|e| TypesError::DecodeError(e.to_string()))?,
                        );
                    }
                }
                Some("seq") => seq = v.as_integer().and_then(|i| u64::try_from(i).ok()),
                Some("published_at") => {
                    published_at = v.as_integer().and_then(|i| u64::try_from(i).ok())
                }
                Some("predecessor") => {
                    if let Some(b) = v.as_bytes() {
                        predecessor = Some(
                            Hash::from_bytes(b)
                                .map_err(|e| TypesError::DecodeError(e.to_string()))?,
                        );
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            peer_id: peer_id
                .ok_or_else(|| TypesError::DecodeError("missing peer_id".into()))?,
            root_hash: root_hash
                .ok_or_else(|| TypesError::DecodeError("missing root_hash".into()))?,
            seq: seq.ok_or_else(|| TypesError::DecodeError("missing seq".into()))?,
            published_at: published_at
                .ok_or_else(|| TypesError::DecodeError("missing published_at".into()))?,
            predecessor,
        })
    }

    /// Encode to an entity. `predecessor` is omitted (key absent) when `None`.
    pub fn to_entity(&self) -> Result<Entity, TypesError> {
        let mut entries = vec![
            (entity_ecf::text("peer_id"), entity_ecf::text(&self.peer_id)),
            (
                entity_ecf::text("published_at"),
                entity_ecf::Value::Integer(self.published_at.into()),
            ),
            (
                entity_ecf::text("root_hash"),
                entity_ecf::Value::Bytes(self.root_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("seq"),
                entity_ecf::Value::Integer(self.seq.into()),
            ),
        ];
        if let Some(pred) = &self.predecessor {
            entries.push((
                entity_ecf::text("predecessor"),
                entity_ecf::Value::Bytes(pred.to_bytes().to_vec()),
            ));
        }
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(entries));
        Entity::new(TYPE_PUBLISHED_ROOT, data)
            .map_err(|e| TypesError::EntityError(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// TypeRegistry
// ---------------------------------------------------------------------------

/// Registry of type definitions.
///
/// Stores type definitions by name for lookup and validation.
/// Thread-safe via interior mutability.
pub struct TypeRegistry {
    definitions: RwLock<BTreeMap<String, TypeDefinition>>,
}

impl TypeRegistry {
    pub fn new() -> Self {
        Self {
            definitions: RwLock::new(BTreeMap::new()),
        }
    }

    /// Register a primitive type (name only, no fields).
    pub fn register_primitive(&self, name: &str) {
        self.definitions
            .write()
            .unwrap()
            .insert(name.to_string(), TypeDefinition::new(name));
    }

    /// Register a fully-specified type definition.
    pub fn register(&self, def: TypeDefinition) {
        self.definitions
            .write()
            .unwrap()
            .insert(def.name.clone(), def);
    }

    /// Look up a type definition by name.
    pub fn get(&self, name: &str) -> Option<TypeDefinition> {
        self.definitions.read().unwrap().get(name).cloned()
    }

    /// Check whether a type is registered.
    pub fn has(&self, name: &str) -> bool {
        self.definitions.read().unwrap().contains_key(name)
    }

    /// Return all registered type definitions, sorted by name.
    pub fn all(&self) -> Vec<TypeDefinition> {
        self.definitions.read().unwrap().values().cloned().collect()
    }

    /// Return the number of registered types.
    pub fn len(&self) -> usize {
        self.definitions.read().unwrap().len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for TypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum TypesError {
    #[error("wrong entity type: expected {expected}, got {actual}")]
    WrongType { expected: String, actual: String },

    #[error("CBOR decode error: {0}")]
    DecodeError(String),

    #[error("entity error: {0}")]
    EntityError(String),

    #[error("type not found: {0}")]
    NotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TypeDefinition tests ---

    #[test]
    fn test_type_definition_new() {
        let td = TypeDefinition::new("test/type");
        assert_eq!(td.name, "test/type");
        assert!(td.fields.is_empty());
        assert!(td.extends.is_none());
    }

    #[test]
    fn test_type_definition_with_fields() {
        let mut fields = BTreeMap::new();
        fields.insert("name".into(), FieldSpec::type_ref("primitive/string"));
        fields.insert("age".into(), FieldSpec::optional("primitive/uint"));
        let td = TypeDefinition::with_fields("test/person", fields);
        assert_eq!(td.fields.len(), 2);
        assert!(td.layout.is_empty(), "layout should be empty unless explicitly set");
    }

    #[test]
    fn test_type_definition_to_entity() {
        let mut fields = BTreeMap::new();
        fields.insert("value".into(), FieldSpec::type_ref("primitive/string"));
        let td = TypeDefinition::with_fields("test/simple", fields);
        let entity = td.to_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_TYPE);
        assert!(entity.validate().is_ok());
    }

    #[test]
    fn test_type_definition_tree_path() {
        let td = TypeDefinition::new("system/handler");
        assert_eq!(td.tree_path(), "system/type/system/handler");
    }

    // --- FieldSpec tests ---

    #[test]
    fn test_field_spec_type_ref() {
        let fs = FieldSpec::type_ref("primitive/string");
        assert_eq!(fs.type_ref, Some("primitive/string".into()));
        assert!(!fs.optional);
    }

    #[test]
    fn test_field_spec_optional() {
        let fs = FieldSpec::optional("primitive/uint");
        assert!(fs.optional);
    }

    #[test]
    fn test_field_spec_array() {
        let fs = FieldSpec::array(FieldSpec::type_ref("primitive/string"));
        assert!(fs.array_of.is_some());
        assert_eq!(
            fs.array_of.unwrap().type_ref,
            Some("primitive/string".into())
        );
    }

    #[test]
    fn test_field_spec_map() {
        let fs = FieldSpec::map(
            FieldSpec::type_ref("primitive/string"),
            Some("primitive/string"),
        );
        assert!(fs.map_of.is_some());
        assert_eq!(fs.key_type, Some("primitive/string".into()));
    }

    // --- TypeRegistry tests ---

    #[test]
    fn test_registry_register_get() {
        let reg = TypeRegistry::new();
        let td = TypeDefinition::new("test/type");
        reg.register(td.clone());
        let got = reg.get("test/type").unwrap();
        assert_eq!(got.name, "test/type");
    }

    #[test]
    fn test_registry_register_primitive() {
        let reg = TypeRegistry::new();
        reg.register_primitive("primitive/string");
        assert!(reg.has("primitive/string"));
        let td = reg.get("primitive/string").unwrap();
        assert!(td.fields.is_empty());
    }

    #[test]
    fn test_registry_has() {
        let reg = TypeRegistry::new();
        assert!(!reg.has("test/type"));
        reg.register(TypeDefinition::new("test/type"));
        assert!(reg.has("test/type"));
    }

    #[test]
    fn test_registry_all_sorted() {
        let reg = TypeRegistry::new();
        reg.register(TypeDefinition::new("z/type"));
        reg.register(TypeDefinition::new("a/type"));
        reg.register(TypeDefinition::new("m/type"));
        let all = reg.all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].name, "a/type");
        assert_eq!(all[1].name, "m/type");
        assert_eq!(all[2].name, "z/type");
    }

    #[test]
    fn test_registry_len() {
        let reg = TypeRegistry::new();
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
        reg.register(TypeDefinition::new("test/a"));
        reg.register(TypeDefinition::new("test/b"));
        assert_eq!(reg.len(), 2);
    }

    // --- PeerData tests ---

    #[test]
    fn test_peer_data_roundtrip() {
        let id = PeerData {
            public_key: vec![1, 2, 3, 4, 5],
            key_type: "ed25519".into(),
        };
        let entity = id.to_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_PEER);
        let decoded = PeerData::from_entity(&entity).unwrap();
        assert_eq!(decoded, id);
    }

    /// V7 §3.5 v7.65 composition: v7.64-shape entities (with peer_id
    /// field in data) decode cleanly into the v7.65 PeerData shape — the
    /// extra peer_id key is silently dropped. Pre-v7.65 cap chains
    /// referencing legacy entities remain verifiable.
    #[test]
    fn test_peer_data_decodes_legacy_v7_64_shape() {
        let legacy = entity_ecf::Value::Map(vec![
            (entity_ecf::text("key_type"), entity_ecf::text("ed25519")),
            (entity_ecf::text("peer_id"), entity_ecf::text("legacy-form-pid")),
            (
                entity_ecf::text("public_key"),
                entity_ecf::Value::Bytes(vec![9, 8, 7]),
            ),
        ]);
        let data = entity_ecf::to_ecf(&legacy);
        let entity = Entity::new(TYPE_PEER, data).unwrap();
        let decoded = PeerData::from_entity(&entity).unwrap();
        assert_eq!(decoded.key_type, "ed25519");
        assert_eq!(decoded.public_key, vec![9, 8, 7]);
    }

    #[test]
    fn test_peer_data_wrong_type() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let entity = Entity::new("wrong/type", data).unwrap();
        assert!(matches!(
            PeerData::from_entity(&entity),
            Err(TypesError::WrongType { .. })
        ));
    }

    // --- SignatureData tests ---

    #[test]
    fn test_signature_data_roundtrip() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("test"));
        let target = Hash::compute("test", &data);
        let signer = Hash::compute("signer", &data);

        let sig = SignatureData {
            target,
            signer,
            algorithm: "ed25519".into(),
            signature: vec![0xAA; 64],
        };
        let entity = sig.to_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_SIGNATURE);
        let decoded = SignatureData::from_entity(&entity).unwrap();
        assert_eq!(decoded, sig);
    }

    #[test]
    fn test_signature_data_wrong_type() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let entity = Entity::new("wrong/type", data).unwrap();
        assert!(matches!(
            SignatureData::from_entity(&entity),
            Err(TypesError::WrongType { .. })
        ));
    }

    #[test]
    fn test_signature_data_entity_validates() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("test"));
        let target = Hash::compute("test", &data);
        let signer = Hash::compute("signer", &data);

        let sig = SignatureData {
            target,
            signer,
            algorithm: "ed25519".into(),
            signature: vec![0xBB; 64],
        };
        let entity = sig.to_entity().unwrap();
        assert!(entity.validate().is_ok());
    }

    // --- PublishedRootData tests ---

    #[test]
    fn test_published_root_roundtrip_with_predecessor() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("root"));
        let root_hash = Hash::compute("root", &data);
        let pred = Hash::compute("pred", &data);

        let pr = PublishedRootData {
            peer_id: "z6MkExampleBase58PeerId".into(),
            root_hash,
            seq: 7,
            published_at: 1_700_000_000_000,
            predecessor: Some(pred),
        };
        let entity = pr.to_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_PUBLISHED_ROOT);
        let decoded = PublishedRootData::from_entity(&entity).unwrap();
        assert_eq!(decoded, pr);
    }

    #[test]
    fn test_published_root_roundtrip_no_predecessor() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("genesis"));
        let root_hash = Hash::compute("genesis", &data);

        let pr = PublishedRootData {
            peer_id: "z6MkGenesis".into(),
            root_hash,
            seq: 0,
            published_at: 1_700_000_000_000,
            predecessor: None,
        };
        let entity = pr.to_entity().unwrap();
        let decoded = PublishedRootData::from_entity(&entity).unwrap();
        assert_eq!(decoded, pr);
        assert!(decoded.predecessor.is_none());
    }

    #[test]
    fn test_published_root_predecessor_key_absent_when_none() {
        // Optional field discipline: absent (no key), not null.
        let data = entity_ecf::to_ecf(&entity_ecf::text("g"));
        let pr = PublishedRootData {
            peer_id: "z6Mk".into(),
            root_hash: Hash::compute("g", &data),
            seq: 1,
            published_at: 42,
            predecessor: None,
        };
        let entity = pr.to_entity().unwrap();
        let value: ciborium::Value =
            ciborium::from_reader(entity.data.as_slice()).unwrap();
        let keys: Vec<&str> = value
            .as_map()
            .unwrap()
            .iter()
            .filter_map(|(k, _)| k.as_text())
            .collect();
        assert!(!keys.contains(&"predecessor"));
    }

    #[test]
    fn test_published_root_wrong_type() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("x"));
        let entity = Entity::new("wrong/type", data).unwrap();
        assert!(matches!(
            PublishedRootData::from_entity(&entity),
            Err(TypesError::WrongType { .. })
        ));
    }
}
