//! Core type definitions for Entity Core Protocol v7.9.
//!
//! Ported from entity-core-rs `native_types.rs` definitions module.
//! All ~70 type definitions covering primitives, meta-types, protocol,
//! capability, handler, tree, and extension types.

use crate::{FieldSpec, TypeDefBuilder, TypeDefinition, TypeRegistry};

// Shorthand helpers matching old native_types.rs conventions.
fn t(name: &str) -> FieldSpec {
    FieldSpec::type_ref(name)
}
fn opt(name: &str) -> FieldSpec {
    FieldSpec::optional(name)
}
fn arr(element: FieldSpec) -> FieldSpec {
    FieldSpec::array(element)
}
fn opt_arr(element: FieldSpec) -> FieldSpec {
    FieldSpec::optional_array(element)
}
fn map(value: FieldSpec) -> FieldSpec {
    FieldSpec::map(value, None)
}
fn opt_map(value: FieldSpec) -> FieldSpec {
    FieldSpec::optional_map(value, None)
}

// ============================================================================
// Bootstrap types (11 total per spec §4.4)
// ============================================================================

fn primitive(name: &str) -> TypeDefinition {
    TypeDefinition::new(name)
}

fn extends(name: &str, parent: &str) -> TypeDefinition {
    TypeDefBuilder::new(name).extends(parent).build()
}

fn primitive_string() -> TypeDefinition {
    primitive("primitive/string")
}
fn primitive_bytes() -> TypeDefinition {
    primitive("primitive/bytes")
}
fn primitive_uint() -> TypeDefinition {
    primitive("primitive/uint")
}
fn primitive_int() -> TypeDefinition {
    primitive("primitive/int")
}
fn primitive_float() -> TypeDefinition {
    primitive("primitive/float")
}
fn primitive_bool() -> TypeDefinition {
    primitive("primitive/bool")
}
fn primitive_null() -> TypeDefinition {
    primitive("primitive/null")
}
fn primitive_any() -> TypeDefinition {
    primitive("primitive/any")
}

/// system/hash — structured primitive (extends bytes with layout).
fn system_hash() -> TypeDefinition {
    TypeDefBuilder::new("system/hash")
        .extends("primitive/bytes")
        .field(
            "format_code",
            FieldSpec::type_ref_with_byte_size("primitive/uint", 1),
        )
        .field("digest", t("primitive/bytes"))
        .layout(vec!["format_code", "digest"])
        .build()
}

// ============================================================================
// Semantic types (§2.6–2.8)
// ============================================================================

fn system_tree_path() -> TypeDefinition {
    extends("system/tree/path", "primitive/string")
}
fn system_type_name() -> TypeDefinition {
    extends("system/type/name", "primitive/string")
}
fn system_peer_id() -> TypeDefinition {
    extends("system/peer-id", "primitive/string")
}

/// `system/deletion-marker` — zero-field canonical entity used by
/// EXTENSION-REVISION to record intentional path deletion in a version's
/// trie. ENTITY-NATIVE-TYPE-SYSTEM §4.9 (v4.2.0). Registered as a core
/// type at peer init alongside the other semantic types. The merge
/// logic that consumes the type lives in EXTENSION-REVISION v3.1, but
/// the type itself is core because deletion semantics are generic.
///
/// Canonical hash: `ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6`.
/// The `data` field for `fields: {}` is the CBOR empty map (`0xa0`),
/// per ECF's standard treatment of zero-field types.
fn system_deletion_marker() -> TypeDefinition {
    TypeDefBuilder::new("system/deletion-marker").build()
}

// ============================================================================
// Meta-types
// ============================================================================

fn system_type() -> TypeDefinition {
    TypeDefBuilder::new("system/type")
        .field("name", t("system/type/name"))
        .field("extends", opt("system/type/name"))
        .field("fields", opt_map(t("system/type/field-spec")))
        .field("layout", opt_arr(t("primitive/string")))
        .field("type_params", opt_arr(t("primitive/string")))
        .field("type_args", opt_map(t("system/type/name")))
        .build()
}

fn system_type_field_spec() -> TypeDefinition {
    TypeDefBuilder::new("system/type/field-spec")
        .field("type_ref", opt("system/type/name"))
        .field("optional", opt("primitive/bool"))
        .field("array_of", opt("system/type/field-spec"))
        .field("map_of", opt("system/type/field-spec"))
        .field("union_of", opt_arr(t("system/type/field-spec")))
        .field("type_param", opt("primitive/string"))
        .field("type_args", opt_map(t("system/type/name")))
        .field("default", opt("primitive/any"))
        .field("key_type", opt("system/type/name"))
        .field("byte_size", opt("primitive/uint"))
        // EXTENSION-TYPE v1.1 §3.3 — open-type constraints. Each entry is a
        // core/entity (a constraint entity dispatched at validate time); peers
        // without the extension preserve it without interpretation.
        .field("constraints", opt_arr(t("core/entity")))
        .build()
}

// ============================================================================
// Core types (§8)
// ============================================================================

/// Bare `entity` — the abstract structural root from which every entity type
/// specializes. `content_hash` is *derived* from `{type, data}` per
/// ENTITY-CBOR-ENCODING §4.2, not declared as a field. The bare name reflects
/// entity's primordial position outside the four-namespace structure
/// (TYPE-SYSTEM §2.7.1, §3.1.1; PROPOSAL-TYPE-NAMESPACE-CONVENTIONS).
fn entity_type() -> TypeDefinition {
    TypeDefBuilder::new("entity")
        .field("type", t("primitive/string"))
        .field("data", t("primitive/any"))
        .build()
}

/// `core/entity` — the materialized form an entity takes once a content hash
/// has been resolved into a slot. Used as a `type_ref` marker in field specs to
/// require "this slot holds a real, identity-bearing entity, not raw CBOR."
/// Lives in `core/*` alongside `core/envelope` (TYPE-SYSTEM §8.1, §2.7.1;
/// PROPOSAL-TYPE-NAMESPACE-CONVENTIONS).
fn core_entity() -> TypeDefinition {
    TypeDefBuilder::new("core/entity")
        .field("type", t("primitive/string"))
        .field("data", t("primitive/any"))
        .field("content_hash", t("system/hash"))
        .build()
}

fn core_envelope() -> TypeDefinition {
    TypeDefBuilder::new("core/envelope")
        .field("root", t("core/entity"))
        .field(
            "included",
            FieldSpec::optional_map(t("core/entity"), Some("system/hash")),
        )
        .build()
}

// ============================================================================
// Protocol types (§9)
// ============================================================================

fn system_protocol_envelope() -> TypeDefinition {
    extends("system/protocol/envelope", "core/envelope")
}

fn system_protocol_connect_hello() -> TypeDefinition {
    TypeDefBuilder::new("system/protocol/connect/hello")
        .field("peer_id", t("system/peer-id"))
        .field("nonce", t("primitive/bytes"))
        .field("protocols", arr(t("primitive/string")))
        .field("timestamp", t("primitive/uint"))
        .field("hash_formats", opt_arr(t("primitive/string")))
        .field("key_types", opt_arr(t("primitive/string")))
        .field("compression", opt_arr(t("primitive/string")))
        .field("encryption", opt_arr(t("primitive/string")))
        .build()
}

fn system_protocol_connect_authenticate() -> TypeDefinition {
    TypeDefBuilder::new("system/protocol/connect/authenticate")
        .field("peer_id", t("system/peer-id"))
        .field("public_key", t("primitive/bytes"))
        .field("key_type", t("primitive/string"))
        .field("nonce", t("primitive/bytes"))
        .build()
}

fn system_protocol_execute() -> TypeDefinition {
    TypeDefBuilder::new("system/protocol/execute")
        .field("request_id", t("primitive/string"))
        .field("uri", t("system/tree/path"))
        .field("operation", t("primitive/string"))
        .field("resource", opt("system/protocol/resource-target"))
        .field("params", t("core/entity"))
        .field("bounds", opt("system/bounds"))
        .field("deliver_to", opt("system/delivery-spec"))
        // EXTENSION-DURABILITY §2: optional request-side durability marker.
        // Extends system/protocol/execute; independent of deliver_to.
        // (Exploratory extension extracted from EXTENSION-INBOX §10;
        // absence is conformant against V7 v7.46.)
        .field("durability_request", opt("system/durability-request"))
        .field("author", opt("system/hash"))
        .field("capability", opt("system/hash"))
        .field("deliver_token", opt("system/hash"))
        .build()
}

fn system_protocol_execute_response() -> TypeDefinition {
    TypeDefBuilder::new("system/protocol/execute/response")
        .field("request_id", t("primitive/string"))
        .field("status", t("primitive/uint"))
        .field("result", t("core/entity"))
        // EXTENSION-DURABILITY §5: the durability verdict. Additive — absent
        // for requests that carry no durability marker, so durability-unaware
        // consumers are unaffected.
        .field("durability", opt("system/durability-result"))
        .build()
}

fn system_protocol_error() -> TypeDefinition {
    TypeDefBuilder::new("system/protocol/error")
        .field("code", t("primitive/string"))
        .field("message", opt("primitive/string"))
        // EXTENSION-CONTINUATION §3.10.4 — optional mirror pointer to the
        // receiver-side `rejected` chain-error marker on a 403 cap-rejection.
        // Additive; envelopes without it stay valid.
        .field("rejected_marker", opt("system/hash"))
        .build()
}

// ============================================================================
// Capability types (§9.8–9.13)
// ============================================================================

fn system_capability_grant() -> TypeDefinition {
    TypeDefBuilder::new("system/capability/grant")
        .field("token", t("system/hash"))
        .build()
}

fn system_capability_path_scope() -> TypeDefinition {
    TypeDefBuilder::new("system/capability/path-scope")
        .field("include", arr(t("system/tree/path")))
        .field("exclude", opt_arr(t("system/tree/path")))
        .build()
}

fn system_capability_id_scope() -> TypeDefinition {
    TypeDefBuilder::new("system/capability/id-scope")
        .field("include", arr(t("primitive/string")))
        .field("exclude", opt_arr(t("primitive/string")))
        .build()
}

fn system_capability_grant_entry() -> TypeDefinition {
    TypeDefBuilder::new("system/capability/grant-entry")
        .field("allowances", FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None))
        .field("handlers", t("system/capability/path-scope"))
        .field("resources", t("system/capability/path-scope"))
        .field("operations", t("system/capability/id-scope"))
        .field("peers", opt("system/capability/id-scope"))
        .field("constraints", FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None))
        .build()
}

fn system_capability_delegation_caveats() -> TypeDefinition {
    TypeDefBuilder::new("system/capability/delegation-caveats")
        .field("no_delegation", opt("primitive/bool"))
        .field("max_delegation_depth", opt("primitive/uint"))
        .field("max_delegation_ttl", opt("primitive/uint"))
        .build()
}

fn system_capability_token() -> TypeDefinition {
    // Per PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.1 (M1): `granter` is
    // polymorphic — `union_of(system/hash, system/capability/multi-granter)`.
    // CBOR major-type discrimination per §M8 (bstr vs map).
    TypeDefBuilder::new("system/capability/token")
        .field("grants", arr(t("system/capability/grant-entry")))
        .field(
            "granter",
            FieldSpec::union(vec![
                FieldSpec::type_ref("system/hash"),
                FieldSpec::type_ref("system/capability/multi-granter"),
            ]),
        )
        .field("grantee", t("system/hash"))
        .field("parent", opt("system/hash"))
        .field("created_at", t("primitive/uint"))
        .field("expires_at", opt("primitive/uint"))
        .field("not_before", opt("primitive/uint"))
        .field(
            "delegation_caveats",
            opt("system/capability/delegation-caveats"),
        )
        .field("resource_limits", opt("system/resource-limits"))
        .build()
}

/// `system/capability/multi-granter` — the K-of-N granter shape per
/// PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.2 (M2). Inline value in the cap's
/// `granter` field when granter is multi-sig (parent must be null per M3).
fn system_capability_multi_granter() -> TypeDefinition {
    TypeDefBuilder::new("system/capability/multi-granter")
        .field("signers", arr(t("system/hash")))
        .field("threshold", t("primitive/uint"))
        .build()
}

fn system_capability_request() -> TypeDefinition {
    TypeDefBuilder::new("system/capability/request")
        .field("grants", arr(t("system/capability/grant-entry")))
        .field("ttl_ms", opt("primitive/uint"))
        .build()
}

fn system_capability_revocation() -> TypeDefinition {
    // V7 §3.6: the persisted marker entity at
    // `system/capability/revocations/{cap_hash_hex}`. `revoked_at` is the
    // handler-set wall-clock millis since Unix epoch; caller-supplied
    // values MUST be ignored (V7 §6.2 cross-cutting timestamp convention).
    TypeDefBuilder::new("system/capability/revocation")
        .field("token", t("system/hash"))
        .field("reason", opt("primitive/string"))
        .field("revoked_at", t("primitive/uint"))
        .build()
}

fn system_capability_revoke_request() -> TypeDefinition {
    // V7 §3.6: input to `system/capability:revoke`. Distinct from
    // `system/capability/revocation` (the persisted marker entity).
    TypeDefBuilder::new("system/capability/revoke-request")
        .field("token", t("system/hash"))
        .field("reason", opt("primitive/string"))
        .build()
}

fn system_capability_delegate_request() -> TypeDefinition {
    // V7 §3.6: input to `system/capability:delegate`. Self-attenuation
    // only — grantee = caller's authenticated identity (no grantee
    // field on the wire).
    TypeDefBuilder::new("system/capability/delegate-request")
        .field("parent", t("system/hash"))
        .field("grants", arr(t("system/capability/grant-entry")))
        .field("ttl_ms", opt("primitive/uint"))
        .build()
}

fn system_capability_policy_entry() -> TypeDefinition {
    // V7 §3.6, §6.2: persisted at
    // `system/capability/policy/{peer_pattern}` where peer_pattern is the
    // 66-hex peer-identity hash (lowercase, format-code byte included) or
    // the literal segment `default` (closeout F8 — was `*` in v7.62;
    // renamed to remove the glyph collision with `*`-as-glob). Consulted
    // by `request` (subset-validation ceiling) and §4.4
    // authenticate-response (union with the SHOULD floor).
    TypeDefBuilder::new("system/capability/policy-entry")
        .field("peer_pattern", t("primitive/string"))
        .field("grants", arr(t("system/capability/grant-entry")))
        .field("ttl_ms", opt("primitive/uint"))
        .field("notes", opt("primitive/string"))
        .build()
}

// ============================================================================
// Supporting types (§10)
// ============================================================================

fn system_peer() -> TypeDefinition {
    TypeDefBuilder::new("system/peer")
        .field("peer_id", t("system/peer-id"))
        .field("public_key", t("primitive/bytes"))
        .field("key_type", t("primitive/string"))
        .build()
}

/// `system/peer/self/status` — the local peer's own runtime status.
/// Per PROPOSAL-RESTART-EQUIVALENCE.md RE-2. Single entity per peer at
/// the canonical path `/{peer_id}/system/peer/self/status`. Class L —
/// updated as the peer transitions through phases (`starting` →
/// `ready` → `draining`).
///
/// `phase` is the externally observable contract: subscribers and
/// remote peers care about one bit — "do I expect responses?".
/// `diagnostic` is an implementer-defined map for fine-grained state
/// (rebuild progress, listener phase, etc.); the cross-impl schema is
/// not yet pinned.
fn system_peer_self_status() -> TypeDefinition {
    TypeDefBuilder::new("system/peer/self/status")
        .field("phase", t("primitive/string"))
        .field("started_at", opt("primitive/uint"))
        .field("last_phase_transition", opt("primitive/uint"))
        .field("diagnostic", opt_map(t("primitive/any")))
        .build()
}

/// `system/peer/published-root` — the signed static anchor for a peer's
/// current tree root (PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE §4,
/// NORMATIVE-LOCKED). `peer_id` is the Base58 id `system/peer-id`
/// per V7 §1.5 (§4 erratum, arch ratification `24a4a97` / Ruling-1 — the
/// originally-locked `<hash>` was corrected to Base58 to match the `http-poll`
/// profile). `root_hash` / `predecessor` are bare `system/hash`. The
/// authenticating signature is carried at the §5.2 invariant-pointer path
/// `system/signature/{hex(content_hash)}`, never a `refs:` block.
fn system_peer_published_root() -> TypeDefinition {
    TypeDefBuilder::new("system/peer/published-root")
        .field("peer_id", t("system/peer-id"))
        .field("root_hash", t("system/hash"))
        .field("seq", t("primitive/uint"))
        .field("published_at", t("primitive/uint"))
        .field("predecessor", opt("system/hash"))
        .build()
}

fn system_signature() -> TypeDefinition {
    TypeDefBuilder::new("system/signature")
        .field("target", t("system/hash"))
        .field("signer", t("system/hash"))
        .field("algorithm", t("primitive/string"))
        .field("signature", t("primitive/bytes"))
        .build()
}

fn system_handler() -> TypeDefinition {
    TypeDefBuilder::new("system/handler")
        .field("interface", t("system/tree/path"))
        .field("max_scope", opt_arr(t("system/capability/grant-entry")))
        .field("internal_scope", opt_arr(t("system/capability/grant-entry")))
        .field("expression_path", opt("system/tree/path"))
        .build()
}

fn system_handler_manifest() -> TypeDefinition {
    TypeDefBuilder::new("system/handler/manifest")
        .extends("system/handler/interface")
        .field("pattern", t("system/tree/path"))
        .field("name", t("primitive/string"))
        .field("operations", map(t("system/handler/operation-spec")))
        .field("max_scope", opt_arr(t("system/capability/grant-entry")))
        .field("internal_scope", opt_arr(t("system/capability/grant-entry")))
        .field("expression_path", opt("system/tree/path"))
        .build()
}

fn system_handler_operation_spec() -> TypeDefinition {
    TypeDefBuilder::new("system/handler/operation-spec")
        .field("input_type", opt("system/type/name"))
        .field("output_type", opt("system/type/name"))
        .build()
}

fn system_handler_interface() -> TypeDefinition {
    TypeDefBuilder::new("system/handler/interface")
        .field("pattern", t("system/tree/path"))
        .field("name", t("primitive/string"))
        .field("operations", map(t("system/handler/operation-spec")))
        .build()
}

fn system_bounds() -> TypeDefinition {
    TypeDefBuilder::new("system/bounds")
        .field("budget", opt("primitive/uint"))
        .field("cascade_depth", opt("primitive/uint"))
        .field("chain_id", opt("primitive/string"))
        .field("parent_chain_id", opt("primitive/string"))
        .field("ttl", opt("primitive/uint"))
        .field("visited", opt_arr(t("system/tree/path")))
        .build()
}

fn system_resource_limits() -> TypeDefinition {
    TypeDefBuilder::new("system/resource-limits")
        .field("max_budget", opt("primitive/uint"))
        .field("max_ttl", opt("primitive/uint"))
        .field("max_visited_length", opt("primitive/uint"))
        .build()
}

// ============================================================================
// Protocol resource target (§3.2)
// ============================================================================

fn system_protocol_resource_target() -> TypeDefinition {
    TypeDefBuilder::new("system/protocol/resource-target")
        .field("targets", arr(t("system/tree/path")))
        .field("exclude", opt_arr(t("system/tree/path")))
        .build()
}

// ============================================================================
// Handler registration types (§6.4)
// ============================================================================

fn system_handler_register_request() -> TypeDefinition {
    TypeDefBuilder::new("system/handler/register-request")
        .field("manifest", t("system/handler/manifest"))
        .field("types", opt_map(t("system/type")))
        .field("requested_scope", opt_arr(t("system/capability/grant-entry")))
        .build()
}

fn system_handler_register_result() -> TypeDefinition {
    TypeDefBuilder::new("system/handler/register-result")
        .field("pattern", t("system/tree/path"))
        .field("grant", t("system/capability/token"))
        .build()
}

// `system/handler/unregister-request` was eliminated by
// PROPOSAL-PATH-AS-RESOURCE-HYGIENE (P-V7-2): unregister derives the pattern
// from `resource = system/handler/{pattern}` and accepts empty params.

// ============================================================================
// Tree types (§10.8)
// ============================================================================

fn system_tree_listing_entry() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/listing-entry")
        .field("hash", opt("system/hash"))
        .field("has_children", t("primitive/bool"))
        .build()
}

fn system_tree_listing() -> TypeDefinition {
    // V7 §3.9 (Amendment 5): optional `next_page` content
    // hash links the head listing to subsequent pages fetched via
    // CONTENT_GET. Absent ⇒ this is the last (or only) page.
    TypeDefBuilder::new("system/tree/listing")
        .field("path", t("system/tree/path"))
        .field("entries", map(t("system/tree/listing-entry")))
        .field("count", t("primitive/uint"))
        .field("offset", t("primitive/uint"))
        .field("next_page", opt("system/hash"))
        .build()
}

fn system_tree_get_request() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/get-request")
        .field("tree_id", opt("primitive/string"))
        .field("mode", opt("primitive/string"))
        .field("limit", opt("primitive/uint"))
        .field("offset", opt("primitive/uint"))
        .build()
}

fn system_tree_put_request() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/put-request")
        .field("entity", FieldSpec::optional("core/entity"))
        .field("expected_hash", opt("system/hash"))
        .field("tree_id", opt("primitive/string"))
        .build()
}

fn system_tree_put_result() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/put-result")
        .field("content_hash", opt("system/hash"))
        .field("removed", opt("primitive/bool"))
        .build()
}

fn system_tree_snapshot_request() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/snapshot-request")
        .field("prefix", opt("system/tree/path"))
        .field("tree_id", opt("primitive/string"))
        .build()
}

fn system_tree_snapshot() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/snapshot")
        .field("prefix", t("system/tree/path"))
        .field("root", t("system/hash"))
        .build()
}

fn system_tree_diff_request() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/diff-request")
        .field("base", t("system/hash"))
        .field("target", t("system/hash"))
        .build()
}

fn system_tree_diff_change() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/diff/change")
        .field("base_hash", t("system/hash"))
        .field("target_hash", t("system/hash"))
        .build()
}

fn system_tree_diff() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/diff")
        .field("added", map(t("system/hash")))
        .field("base", t("system/hash"))
        .field("changed", map(t("system/tree/diff/change")))
        .field("removed", map(t("system/hash")))
        .field("target", t("system/hash"))
        .field("unchanged", t("primitive/uint"))
        .build()
}

fn system_tree_merge_request() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/merge-request")
        .field("source", t("system/hash"))
        .field("strategy", opt("primitive/string"))
        .field("source_prefix", opt("system/tree/path"))
        .field("target_prefix", opt("system/tree/path"))
        .field("dry_run", opt("primitive/bool"))
        .build()
}

fn system_tree_merge_conflict() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/merge-result/conflict")
        .field("existing_hash", t("system/hash"))
        .field("incoming_hash", t("system/hash"))
        .field("resolution", t("primitive/string"))
        .build()
}

fn system_tree_merge_result() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/merge-result")
        .field("applied", t("primitive/uint"))
        .field("conflicts", map(t("system/tree/merge-result/conflict")))
        .field("skipped", t("primitive/uint"))
        .field("strategy", t("primitive/string"))
        .build()
}

fn system_tree_extract_request() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/extract-request")
        .field("prefix", opt("system/tree/path"))
        .field("tree_id", opt("primitive/string"))
        .field("paths", opt_arr(t("system/tree/path")))
        .build()
}

fn system_tree_tracking_config() -> TypeDefinition {
    // EXTENSION-TREE §3.4.1a — incremental trie root tracking configuration.
    TypeDefBuilder::new("system/tree/tracking-config")
        .field("prefix", t("system/tree/path"))
        .field("enabled", t("primitive/bool"))
        .build()
}

// ============================================================================
// Content types
// ============================================================================

// EXTENSION-CONTENT v3.5 §2.1 — content blob manifest. Chunk list is a
// flat array of `system/hash` records per ENTITY-NATIVE-TYPE-SYSTEM §2.8
// (`array_of` over a named non-`core/entity` type → flat records, not
// `{type, data, content_hash}` envelopes).
fn system_content_blob() -> TypeDefinition {
    TypeDefBuilder::new("system/content/blob")
        .field("total_size", t("primitive/uint"))
        .field("chunk_size", t("primitive/uint"))
        .field("chunking", t("primitive/uint"))
        .field("chunks", arr(t("system/hash")))
        .build()
}

// EXTENSION-CONTENT v3.5 §2.2 — chunk payload. No sequence, no parent,
// no metadata — deliberate so identical payloads dedupe to the same hash.
fn system_content_chunk() -> TypeDefinition {
    TypeDefBuilder::new("system/content/chunk")
        .field("payload", t("primitive/bytes"))
        .build()
}

// EXTENSION-CONTENT v3.5 §2.4 — consumption-format declaration over a
// blob. At least one of `media_type` or `type_ref` MUST be present (the
// presence rule is enforced at handler/consumer level, not via the type
// system); both MAY be present. `type_ref` composes with EXTENSION-TYPE
// when installed.
fn system_content_descriptor() -> TypeDefinition {
    TypeDefBuilder::new("system/content/descriptor")
        .field("content", t("system/hash"))
        .field("media_type", opt("primitive/string"))
        .field("type_ref", opt("system/hash"))
        .field("name", opt("primitive/string"))
        .field("metadata", opt("primitive/any"))
        .build()
}

// EXTENSION-CONTENT v3.5 §6.2 — `system/content:get` request.
fn system_content_get_request() -> TypeDefinition {
    TypeDefBuilder::new("system/content/get-request")
        .field("hashes", arr(t("system/hash")))
        .build()
}

// EXTENSION-CONTENT v3.5 §6.2 — shared response shape for
// `system/content:get` (and for domain `<handler>:get-request` ops per
// §4.2). Resolved entities ride in the response envelope's `included`
// map.
fn system_content_content_response() -> TypeDefinition {
    TypeDefBuilder::new("system/content/content-response")
        .field("found", arr(t("system/hash")))
        .field("missing", arr(t("system/hash")))
        .build()
}

fn system_content_ingest_request() -> TypeDefinition {
    // EXTENSION-CONTENT §6.3 supports two modes:
    //   - Entity mode: caller passes a single `entity` (legacy / direct callers)
    //   - Envelope mode: caller passes a `system/envelope` (chain composition
    //     pattern, per PROPOSAL-CONTENT-INGEST-PASS-THROUGH).
    // Exactly one of the two MUST be present.
    TypeDefBuilder::new("system/content/ingest-request")
        .field("entity", FieldSpec::optional("core/entity"))
        .field("envelope", FieldSpec::optional("system/envelope"))
        .build()
}

fn system_content_ingest_result() -> TypeDefinition {
    // EXTENSION-CONTENT §6.3 amended by PROPOSAL-CONTENT-INGEST-PASS-THROUGH.
    // When ingest was called in envelope mode with a
    // non-null `envelope.root`, the result carries `root` — the original
    // envelope root entity inlined — so downstream continuation chain steps
    // can navigate `data.root.data.X` to extract semantic fields from the
    // wrapper without dereferencing the content store. Absent in entity mode.
    //
    // Existing callers that read only `root_hash` and `ingested_count`
    // continue to work — `root` is optional.
    //
    // The Rust kernel does not yet ship a `content:ingest` handler
    // implementation (only the type definitions). This shape is registered
    // so the type system carries the spec-correct shape ahead of the
    // handler landing. See EXTENSION-CONTENT.md §6.3 v3.4.
    TypeDefBuilder::new("system/content/ingest-result")
        .field("root", FieldSpec::optional("core/entity"))
        .field("root_hash", t("system/hash"))
        .field("ingested_count", t("primitive/uint"))
        .build()
}

// ============================================================================
// Validation types
// ============================================================================

// EXTENSION-TYPE v1.1 §8.3: validate-request carries the entity to validate
// and an optional explicit type path. When `type_path` is absent, the
// validator uses `entity.type` (resolved via Strategy 1 path lookup).
fn system_type_validate_request() -> TypeDefinition {
    TypeDefBuilder::new("system/type/validate-request")
        .field("entity", t("core/entity"))
        .field("type_path", opt("system/type/name"))
        .build()
}

// EXTENSION-TYPE v1.1 §8.4: validate-result carries violations[] (typed)
// and unevaluated_fields[] (open-type extension fields the validator
// detected but couldn't interpret). `errors` is gone — replaced by
// `violations` carrying kind/constraint/reason.
fn system_type_validate_result() -> TypeDefinition {
    TypeDefBuilder::new("system/type/validate-result")
        .field("valid", t("primitive/bool"))
        .field("violations", opt_arr(t("system/type/violation")))
        .field("unevaluated_fields", opt_arr(t("primitive/string")))
        .build()
}

// EXTENSION-TYPE v1.1 §8.5: violation entity reported in validate-result.
// kind ∈ {"structural", "constraint", "unknown_constraint"} per §1.2.
fn system_type_violation() -> TypeDefinition {
    TypeDefBuilder::new("system/type/violation")
        .field("field", t("primitive/string"))
        .field("kind", t("primitive/string"))
        .field("constraint", opt("system/type/name"))
        .field("reason", t("primitive/string"))
        .build()
}

// EXTENSION-TYPE v1.1 §5.2 — constraint dispatch envelope (request).
// Carries the field value, the constraint type path, and the constraint's
// data (raw CBOR — typed `primitive/any` so any constraint shape fits).
fn system_type_constraint_validate_request() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/validate-request")
        .field("value", t("primitive/any"))
        .field("constraint_type", t("system/type/name"))
        .field("constraint_data", t("primitive/any"))
        .build()
}

// EXTENSION-TYPE v1.1 §5.3 — constraint dispatch envelope (result).
fn system_type_constraint_validate_result() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/validate-result")
        .field("valid", t("primitive/bool"))
        .field("reason", opt("primitive/string"))
        .build()
}

// EXTENSION-TYPE v1.1 §4 — 11 standard constraint type definitions.
// Each is a `system/type` entity at `system/type/constraint/{kind}`. The
// standard constraint handler at `system/type/constraint/*` evaluates
// these via §5.4 dispatch.

fn system_type_constraint_min() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/min")
        .field("min", t("primitive/float"))
        .build()
}

fn system_type_constraint_max() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/max")
        .field("max", t("primitive/float"))
        .build()
}

fn system_type_constraint_min_length() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/min-length")
        .field("min_length", t("primitive/uint"))
        .build()
}

fn system_type_constraint_max_length() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/max-length")
        .field("max_length", t("primitive/uint"))
        .build()
}

fn system_type_constraint_min_count() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/min-count")
        .field("min_count", t("primitive/uint"))
        .build()
}

fn system_type_constraint_max_count() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/max-count")
        .field("max_count", t("primitive/uint"))
        .build()
}

fn system_type_constraint_pattern() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/pattern")
        .field("pattern", t("primitive/string"))
        .build()
}

fn system_type_constraint_one_of() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/one-of")
        .field("values", arr(t("primitive/any")))
        .build()
}

fn system_type_constraint_not_one_of() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/not-one-of")
        .field("values", arr(t("primitive/any")))
        .build()
}

fn system_type_constraint_format() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/format")
        .field("format", t("primitive/string"))
        .build()
}

fn system_type_constraint_type_pattern() -> TypeDefinition {
    TypeDefBuilder::new("system/type/constraint/type-pattern")
        .field("pattern", t("primitive/string"))
        .build()
}

// EXTENSION-TYPE v1.1 §8 — analysis-op support types. compare / compatible
// land in R-T5 (SHOULD); the types are registered here so the spec-correct
// shape is carried by the type system ahead of the handler ops.

fn system_type_field_comparison() -> TypeDefinition {
    TypeDefBuilder::new("system/type/field-comparison")
        .field("type_match", t("primitive/bool"))
        .field("constraint_match", t("primitive/bool"))
        .field("a_optional", t("primitive/bool"))
        .field("b_optional", t("primitive/bool"))
        .field("detail", opt("primitive/string"))
        .build()
}

fn system_type_field_incompatibility() -> TypeDefinition {
    TypeDefBuilder::new("system/type/field-incompatibility")
        .field("field_name", t("primitive/string"))
        .field("a_type", t("system/type/name"))
        .field("b_type", t("system/type/name"))
        .field("reason", t("primitive/string"))
        .build()
}

fn system_type_compare_request() -> TypeDefinition {
    TypeDefBuilder::new("system/type/compare-request")
        .field("type_a", t("system/tree/path"))
        .field("type_b", t("system/tree/path"))
        .build()
}

fn system_type_compare_result() -> TypeDefinition {
    TypeDefBuilder::new("system/type/compare-result")
        .field("type_a_path", t("system/tree/path"))
        .field("type_b_path", t("system/tree/path"))
        .field("shared", map(t("system/type/field-comparison")))
        .field("only_a", arr(t("primitive/string")))
        .field("only_b", arr(t("primitive/string")))
        .field("incompatible", opt_arr(t("system/type/field-incompatibility")))
        .build()
}

fn system_type_compatible_request() -> TypeDefinition {
    TypeDefBuilder::new("system/type/compatible-request")
        .field("type_a", t("system/tree/path"))
        .field("type_b", t("system/tree/path"))
        .field("direction", t("primitive/string"))
        .build()
}

fn system_type_compatibility_report() -> TypeDefinition {
    TypeDefBuilder::new("system/type/compatibility-report")
        .field("type_a_path", t("system/tree/path"))
        .field("type_b_path", t("system/tree/path"))
        .field("direction", t("primitive/string"))
        .field("level", t("primitive/string"))
        .field("shared_fields", arr(t("primitive/string")))
        .field("incompatible_fields", opt_arr(t("system/type/field-incompatibility")))
        .field("missing_required_a", opt_arr(t("primitive/string")))
        .field("missing_required_b", opt_arr(t("primitive/string")))
        .build()
}

// ============================================================================
// Delivery spec
// ============================================================================

fn system_delivery_spec() -> TypeDefinition {
    TypeDefBuilder::new("system/delivery-spec")
        .field("uri", t("system/tree/path"))
        .field("operation", t("primitive/string"))
        .build()
}

// ============================================================================
// Durability contract (EXTENSION-DURABILITY v0.1)
// ============================================================================

// §2 — optional request-side durability marker. `level` vocabulary is
// illustrative, not a frozen enum (§7). `must_have` defaults false
// (best-effort); true means refuse if unmet (412, §5).
fn system_durability_request() -> TypeDefinition {
    TypeDefBuilder::new("system/durability-request")
        .field("level", t("primitive/string"))
        .field("must_have", opt("primitive/bool"))
        .build()
}

// §5 — the pinned response verdict shape. `applied` = durability PHYSICALLY
// IN PLACE at response time (never a promise). `committed` present ONLY with
// status 202; `max_available` present ONLY with status 412.
fn system_durability_result() -> TypeDefinition {
    TypeDefBuilder::new("system/durability-result")
        .field("requested", t("primitive/string"))
        .field("applied", t("primitive/string"))
        .field("committed", opt("primitive/string"))
        .field("max_available", opt("primitive/string"))
        .field("reason", opt("primitive/string"))
        // §6 / Amendment 1 — absolute tree path where the durable entry can
        // be read; present when applied != none. Typed `primitive/string` to
        // match Go's registry declaration (cross-impl hash agreement).
        .field("handle", opt("primitive/string"))
        .build()
}

// §3 — durability advertisement. The receiver MAY bind one of these at a
// receiver-chosen path (this peer uses `/{peer_id}/system/durability`) so
// senders can discover supported levels before issuing a request.
fn system_durability_advertisement() -> TypeDefinition {
    TypeDefBuilder::new("system/durability-advertisement")
        .field("levels", arr(t("primitive/string")))
        .field("max_self_determinable", t("primitive/string"))
        .build()
}

// ============================================================================
// Subscription extension types
// ============================================================================

fn system_subscription() -> TypeDefinition {
    TypeDefBuilder::new("system/subscription")
        .field("subscription_id", t("primitive/string"))
        .field("pattern", t("system/tree/path"))
        .field("events", arr(t("primitive/string")))
        .field("deliver_uri", t("system/tree/path"))
        .field("deliver_operation", t("primitive/string"))
        .field("subscriber_identity", t("system/hash"))
        .field("deliver_token", t("system/hash"))
        .field("created_at", t("primitive/uint"))
        .field("limits", opt("system/subscription/limits"))
        // EXTENSION-SUBSCRIPTION §2.1 (v3.12+) — persisted opt-in flag; engine
        // reads it at delivery to bundle the changed entity. Default false.
        .field("include_payload", opt("primitive/bool"))
        .build()
}

fn system_subscription_request() -> TypeDefinition {
    TypeDefBuilder::new("system/subscription/request")
        .field("events", opt_arr(t("primitive/string")))
        .field("deliver_to", t("system/delivery-spec"))
        .field("deliver_token", t("system/hash"))
        .field("limits", opt("system/subscription/limits"))
        // EXTENSION-SUBSCRIPTION §2.3 (v3.12+) — opt-in request to bundle the
        // changed entity into delivery (subject to the §2.3 read-auth check).
        .field("include_payload", opt("primitive/bool"))
        .build()
}

fn system_subscription_cancel() -> TypeDefinition {
    TypeDefBuilder::new("system/subscription/cancel")
        .field("subscription_id", t("primitive/string"))
        .build()
}

fn system_subscription_limits() -> TypeDefinition {
    TypeDefBuilder::new("system/subscription/limits")
        .field("max_events", opt("primitive/uint"))
        .field("max_duration_ms", opt("primitive/uint"))
        .field("rate_limit", opt("primitive/uint"))
        .field("notification_budget", opt("primitive/uint"))
        .build()
}

fn system_subscription_redirect() -> TypeDefinition {
    TypeDefBuilder::new("system/subscription/redirect")
        .field("reason", t("primitive/string"))
        .field("prefix", t("system/tree/path"))
        .field("alternatives", opt_arr(t("system/hash")))
        .field("capacity", opt("primitive/uint"))
        .build()
}

fn system_config_subscription() -> TypeDefinition {
    TypeDefBuilder::new("system/config/subscription")
        .field("max_subscribers_per_prefix", opt("primitive/uint"))
        .build()
}

// ============================================================================
// Inbox extension types
// ============================================================================

fn system_inbox_delivery() -> TypeDefinition {
    TypeDefBuilder::new("system/protocol/inbox/delivery")
        .field("original_request_id", t("primitive/string"))
        .field("status", t("primitive/uint"))
        .field("result", t("core/entity"))
        .build()
}

fn system_inbox_notification() -> TypeDefinition {
    TypeDefBuilder::new("system/protocol/inbox/notification")
        .field("subscription_id", t("primitive/string"))
        .field("event", t("primitive/string"))
        .field("uri", t("system/tree/path"))
        .field("hash", opt("system/hash"))
        .field("previous_hash", opt("system/hash"))
        .build()
}

// ============================================================================
// Continuation extension types
// ============================================================================

fn system_continuation() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation")
        .field("target", t("system/tree/path"))
        .field("operation", t("primitive/string"))
        .field("resource", opt("system/protocol/resource-target"))
        .field("params", opt("primitive/any"))
        .field("result_transform", opt("system/continuation/transform"))
        .field("result_field", opt("primitive/string"))
        // EXTENSION-CONTINUATION v1.16 §2.1 — Merge mode: shallow-merge the
        // post-transform map result into static `params`. Mutually exclusive
        // with `result_field` (install rejects 400). Default/absent = false.
        .field("result_merge", opt("primitive/bool"))
        .field("on_error", opt("system/delivery-spec"))
        .field("deliver_to", opt("system/delivery-spec"))
        .field("remaining_executions", opt("primitive/uint"))
        .field("dispatch_capability", opt("system/hash"))
        .build()
}

fn system_continuation_transform() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation/transform")
        .field("extract", opt("primitive/string"))
        .field("select", opt_map(t("primitive/string")))
        // EXTENSION-CONTINUATION v1.9 G1 §2.2: ordered closed/total/pure/bounded
        // field ops applied after extract/select, before the *_extract fields.
        .field("transform_ops", opt_arr(t("system/continuation/transform-op")))
        .field("resource_extract", opt("primitive/string"))
        .field("target_extract", opt("primitive/string"))
        .field("operation_extract", opt("primitive/string"))
        .build()
}

/// EXTENSION-CONTINUATION v1.9 §2.2: one bounded field operation within a
/// transform's `transform_ops`. `op` is the operation name (table in §2.2);
/// the remaining fields are operands, each optional and interpreted per-op.
fn system_continuation_transform_op() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation/transform-op")
        .field("op", t("primitive/string"))
        .field("field", opt("primitive/string"))
        .field("into", opt("primitive/string"))
        .field("fields", opt_arr(t("primitive/string")))
        .field("prefix", opt("primitive/string"))
        .field("literal", opt("primitive/string"))
        .field("from", opt("primitive/string"))
        .field("to", opt("primitive/string"))
        .field("sep", opt("primitive/string"))
        .field("range", opt("primitive/string"))
        .build()
}

fn system_continuation_join() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation/join")
        .field("expected", arr(t("primitive/string")))
        .field("received", opt_map(t("primitive/any")))
        .field("target", t("system/tree/path"))
        .field("operation", t("primitive/string"))
        .field("resource", opt("system/protocol/resource-target"))
        .field("params", opt("primitive/any"))
        .field("result_field", opt("primitive/string"))
        .field("on_error", opt("system/delivery-spec"))
        .field("deliver_to", opt("system/delivery-spec"))
        .field("remaining_executions", opt("primitive/uint"))
        .field("dispatch_capability", opt("system/hash"))
        .build()
}

fn system_continuation_suspended() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation/suspended")
        .field("target", t("system/tree/path"))
        .field("operation", t("primitive/string"))
        .field("resource", opt("system/protocol/resource-target"))
        .field("params", opt("primitive/any"))
        .field("reason", t("primitive/string"))
        .field("chain_id", t("primitive/string"))
        .field("original_author", t("system/hash"))
        .field("suspended_at", t("primitive/uint"))
        .build()
}

fn system_continuation_advance_request() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation/advance-request")
        .field("result", opt("primitive/any"))
        .field("status", opt("primitive/uint"))
        .build()
}

fn system_continuation_resume_request() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation/resume-request")
        .field("bounds", opt("system/bounds"))
        .field("resolution", opt("primitive/any"))
        .field("deliver_to", opt("system/delivery-spec"))
        .build()
}

fn system_continuation_abandon_request() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation/abandon-request").build()
}

fn system_continuation_advance_result() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation/advance-result")
        .field("advanced", t("primitive/bool"))
        .field("exhausted", opt("primitive/bool"))
        .field("suspended", opt("primitive/bool"))
        .field("error_routed", opt("primitive/bool"))
        .field("suspended_path", opt("system/tree/path"))
        .build()
}

/// EXTENSION-CONTINUATION v1.7 §2.7: retained for forward-compat after the
/// install-request wrapper was eliminated by PROPOSAL-PATH-AS-RESOURCE-HYGIENE.
/// Echoes the suspended path where the continuation was installed.
fn system_continuation_install_result() -> TypeDefinition {
    TypeDefBuilder::new("system/continuation/install-result")
        .field("path", t("system/tree/path"))
        .build()
}

// ============================================================================
// Clock extension types (EXTENSION-CLOCK §2)
// ============================================================================

fn system_clock_timestamp() -> TypeDefinition {
    TypeDefBuilder::new("system/clock/timestamp")
        .field("ms", t("primitive/uint"))
        .build()
}

fn system_clock_logical() -> TypeDefinition {
    TypeDefBuilder::new("system/clock/logical")
        .field("counter", t("primitive/uint"))
        .build()
}

fn system_clock_vector() -> TypeDefinition {
    TypeDefBuilder::new("system/clock/vector")
        .field("entries", map(t("primitive/uint")))
        .build()
}

fn system_clock_hlc() -> TypeDefinition {
    TypeDefBuilder::new("system/clock/hlc")
        .field("logical", t("primitive/uint"))
        .field("peer", t("system/hash"))
        .field("physical", t("primitive/uint"))
        .build()
}

fn system_clock_config() -> TypeDefinition {
    TypeDefBuilder::new("system/clock/config")
        .field("mode", t("primitive/string"))
        .field("tick_interval", opt("primitive/uint"))
        .field("wall_clock", opt("primitive/bool"))
        .build()
}

fn system_clock_state() -> TypeDefinition {
    TypeDefBuilder::new("system/clock/state")
        .field("hlc", opt("system/clock/hlc"))
        .field("logical", opt("system/clock/logical"))
        .field("mode", t("primitive/string"))
        .field("timestamp", opt("system/clock/timestamp"))
        .field("vector", opt("system/clock/vector"))
        .build()
}

fn system_clock_compare_params() -> TypeDefinition {
    TypeDefBuilder::new("system/clock/compare-params")
        .field("a", t("primitive/any"))
        .field("b", t("primitive/any"))
        .build()
}

fn system_clock_compare_result() -> TypeDefinition {
    TypeDefBuilder::new("system/clock/compare-result")
        .field("order", t("primitive/string"))
        .build()
}

fn system_clock_tick() -> TypeDefinition {
    TypeDefBuilder::new("system/clock/tick")
        .field("sequence", t("primitive/uint"))
        .field("state", t("system/clock/state"))
        .build()
}

// ============================================================================
// Tree snapshot node (trie) type (EXTENSION-TREE §3.3)
// ============================================================================

fn system_tree_snapshot_node() -> TypeDefinition {
    TypeDefBuilder::new("system/tree/snapshot/node")
        .field("binding", opt("system/hash"))
        .field("entries", opt_map(t("system/hash")))
        .build()
}

// ============================================================================
// Revision extension types (EXTENSION-REVISION §2)
// ============================================================================

fn system_revision_entry() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/entry")
        .field("parents", arr(t("system/hash")))
        .field("root", t("system/hash"))
        .build()
}

fn system_revision_conflict() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/conflict")
        .field("base", opt("system/hash"))
        .field("local", opt("system/hash"))
        .field("path", t("primitive/string"))
        .field("remote", opt("system/hash"))
        .field("strategy", t("primitive/string"))
        .field("supersedes", opt("system/hash"))
        .field("version_local", t("system/hash"))
        .field("version_remote", t("system/hash"))
        .build()
}

fn system_revision_config_params() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/config-params")
        .field("name", t("primitive/string"))
        .field("action", t("primitive/string"))
        .field("config", opt("system/revision/config"))
        .field("expected_hash", opt("system/hash"))
        .build()
}

fn system_revision_config_result() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/config-result")
        .field("config_path", t("system/tree/path"))
        .field("config_hash", opt("system/hash"))
        .field("previous_hash", opt("system/hash"))
        .field("tracking_config_path", opt("system/tree/path"))
        .field("tracking_config_action", opt("primitive/string"))
        .build()
}

fn system_revision_cascade_warning() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/cascade-warning")
        .field("path", t("system/tree/path"))
        .field("consumer_halted", t("primitive/string"))
        .field("error_code", t("primitive/string"))
        .build()
}

fn system_revision_commit_params() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/commit-params")
        .field("prefix", t("primitive/string"))
        .build()
}

fn system_revision_commit_result() -> TypeDefinition {
    // EXTENSION-REVISION §4.3.1 (line 699): data = {version, root}.
    TypeDefBuilder::new("system/revision/commit-result")
        .field("root", t("system/hash"))
        .field("version", t("system/hash"))
        .build()
}

fn system_revision_merge_result() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/merge-result")
        .field("cascade_warnings", opt_arr(t("system/revision/cascade-warning")))
        .field("conflicts", opt_arr(t("primitive/string")))
        .field("deleted_count", opt("primitive/uint"))
        .field("merged_count", opt("primitive/uint"))
        .field("status", t("primitive/string"))
        .field("version", opt("system/hash"))
        .build()
}

fn system_revision_checkout_result() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/checkout-result")
        .field("branch", opt("primitive/string"))
        .field("cascade_warnings", opt_arr(t("system/revision/cascade-warning")))
        .field("head", t("system/hash"))
        .field("note", opt("primitive/string"))
        .field("status", t("primitive/string"))
        .field("target_version", t("system/hash"))
        .field("version", t("system/hash"))
        .build()
}

fn system_revision_cherry_pick_result() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/cherry-pick-result")
        .field("cascade_warnings", opt_arr(t("system/revision/cascade-warning")))
        .field("conflicts", opt("primitive/uint"))
        .field("source", t("system/hash"))
        .field("status", t("primitive/string"))
        .field("version", t("system/hash"))
        .build()
}

fn system_revision_revert_result() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/revert-result")
        .field("cascade_warnings", opt_arr(t("system/revision/cascade-warning")))
        .field("conflicts", opt("primitive/uint"))
        .field("reverted", t("system/hash"))
        .field("status", t("primitive/string"))
        .field("version", t("system/hash"))
        .build()
}

fn system_revision_branch_result() -> TypeDefinition {
    TypeDefBuilder::new("system/revision/branch-result")
        .field("active", opt("primitive/string"))
        .field("branch", opt("primitive/string"))
        .field("branches", opt_map(t("system/hash")))
        .field("status", opt("primitive/string"))
        .field("version", opt("system/hash"))
        .build()
}

// ============================================================================
// Compute extension types (EXTENSION-COMPUTE §2)
// ============================================================================

fn compute_literal() -> TypeDefinition {
    TypeDefBuilder::new("compute/literal")
        .field("value", t("primitive/any"))
        .build()
}

fn compute_lookup_scope() -> TypeDefinition {
    TypeDefBuilder::new("compute/lookup/scope")
        .field("name", t("primitive/string"))
        .build()
}

fn compute_lookup_tree() -> TypeDefinition {
    // CROSS-IMPL-RUST: `relative` optional bool aligns with Go's
    // type-def for relative-path lookups (Types §12.3).
    TypeDefBuilder::new("compute/lookup/tree")
        .field("path", t("system/tree/path"))
        .field("relative", opt("primitive/bool"))
        .build()
}

fn compute_apply() -> TypeDefinition {
    // CROSS-IMPL-RUST: `resource` and `capability` optional
    // hashes align with Go's type-def — apply may carry resource scope
    // and capability metadata for the called op (Types §12.3).
    TypeDefBuilder::new("compute/apply")
        .field("path", opt("system/tree/path"))
        .field("operation", opt("primitive/string"))
        .field("fn", opt("system/hash"))
        .field("args", opt_map(t("system/hash")))
        .field("resource", opt("system/hash"))
        .field("capability", opt("system/hash"))
        .build()
}

fn compute_if() -> TypeDefinition {
    TypeDefBuilder::new("compute/if")
        .field("condition", t("system/hash"))
        .field("then", t("system/hash"))
        .field("else", opt("system/hash"))
        .build()
}

fn compute_let() -> TypeDefinition {
    TypeDefBuilder::new("compute/let")
        .field("bindings", arr(t("primitive/any")))
        .field("body", t("system/hash"))
        .build()
}

fn compute_lambda() -> TypeDefinition {
    TypeDefBuilder::new("compute/lambda")
        .field("params", arr(t("primitive/string")))
        .field("body", t("system/hash"))
        .build()
}

fn compute_arithmetic() -> TypeDefinition {
    TypeDefBuilder::new("compute/arithmetic")
        .field("op", t("primitive/string"))
        .field("left", t("system/hash"))
        .field("right", t("system/hash"))
        .build()
}

fn compute_compare() -> TypeDefinition {
    TypeDefBuilder::new("compute/compare")
        .field("op", t("primitive/string"))
        .field("left", t("system/hash"))
        .field("right", t("system/hash"))
        .build()
}

fn compute_logic() -> TypeDefinition {
    TypeDefBuilder::new("compute/logic")
        .field("op", t("primitive/string"))
        .field("left", t("system/hash"))
        .field("right", opt("system/hash"))
        .build()
}

fn compute_field() -> TypeDefinition {
    TypeDefBuilder::new("compute/field")
        .field("name", t("primitive/string"))
        .field("entity", t("system/hash"))
        .build()
}

fn compute_construct() -> TypeDefinition {
    TypeDefBuilder::new("compute/construct")
        .field("entity_type", t("system/type/name"))
        .field("fields", map(t("system/hash")))
        .build()
}

fn compute_lookup_hash() -> TypeDefinition {
    // CROSS-IMPL-RUST: `relative` optional bool aligns with
    // Go's type-def (Types §12.3).
    TypeDefBuilder::new("compute/lookup/hash")
        .field("hash", t("system/hash"))
        .field("path", opt("system/tree/path"))
        .field("relative", opt("primitive/bool"))
        .build()
}

fn compute_closure() -> TypeDefinition {
    TypeDefBuilder::new("compute/closure")
        .field("params", arr(t("primitive/string")))
        .field("body", t("system/hash"))
        .field("env", opt("system/hash"))
        .build()
}

fn compute_scope() -> TypeDefinition {
    // v3.19b §2.3: bindings are kind-tagged scope-binding values.
    TypeDefBuilder::new("compute/scope")
        .field("bindings", map(t("system/compute/scope-binding")))
        .build()
}

/// v3.19b §2.3: a scope binding is a discriminated union —
/// `{kind: "entity", entity_hash: <hash>}` or `{kind: "value", value: <bare>}`.
/// Both shapes share the `kind` discriminator; `entity_hash` and `value` are
/// optional, with exactly one present depending on kind (N1 reference-don't-
/// duplicate). The type def is permissive (optional fields); validation of the
/// shape invariant lives in the compute evaluator.
fn system_compute_scope_binding() -> TypeDefinition {
    TypeDefBuilder::new("system/compute/scope-binding")
        .field("kind", t("primitive/string"))
        .field("entity_hash", opt("system/hash"))
        .field("value", opt("primitive/any"))
        .build()
}

fn compute_result() -> TypeDefinition {
    TypeDefBuilder::new("compute/result")
        .field("value", t("primitive/any"))
        .field("expression", t("system/hash"))
        .build()
}

fn compute_error() -> TypeDefinition {
    TypeDefBuilder::new("compute/error")
        .field("code", t("primitive/string"))
        .field("message", t("primitive/string"))
        .field("at", opt("primitive/string"))
        .field("expression", opt("system/hash"))
        .build()
}

fn system_compute_subgraph() -> TypeDefinition {
    // CROSS-IMPL-RUST: `authorized_data_hashes` optional array
    // of hashes aligns with Go's type-def (Types §12.3).
    TypeDefBuilder::new("system/compute/subgraph")
        .field("root_expression_path", t("system/tree/path"))
        .field("root_expression", t("system/hash"))
        .field("installation_grant", t("system/hash"))
        .field("installed_by", t("system/hash"))
        .field("result_path", t("system/tree/path"))
        .field("status", t("primitive/string"))
        .field(
            "authorized_data_hashes",
            FieldSpec::optional_array(FieldSpec::type_ref("system/hash")),
        )
        .build()
}

fn system_compute_install_request() -> TypeDefinition {
    // root_expression_path moved to `resource` per
    // PROPOSAL-PATH-AS-RESOURCE-HYGIENE P-COMPUTE-2; result_path remains
    // (handler-write target, not an authorization target).
    TypeDefBuilder::new("system/compute/install-request")
        .field("result_path", opt("system/tree/path"))
        .build()
}

fn system_compute_install_result() -> TypeDefinition {
    TypeDefBuilder::new("system/compute/install-result")
        .field("subgraph_path", t("system/tree/path"))
        .field("impure_operations", t("primitive/any"))
        .field("result_path", t("system/tree/path"))
        .build()
}

// `system/compute/uninstall-request` was eliminated by
// PROPOSAL-PATH-AS-RESOURCE-HYGIENE (P-COMPUTE-3): uninstall derives the
// subgraph path from `resource` and accepts empty params.

fn system_compute_store_args() -> TypeDefinition {
    TypeDefBuilder::new("system/compute/store-args")
        .field("path", t("system/tree/path"))
        .field("value", t("system/hash"))
        .build()
}

// EXTENSION-COMPUTE v3.14 N.1 — new core inline expression types.
fn compute_index() -> TypeDefinition {
    TypeDefBuilder::new("compute/index")
        .field("array", t("system/hash"))
        .field("index", t("system/hash"))
        .build()
}

fn compute_length() -> TypeDefinition {
    TypeDefBuilder::new("compute/length")
        .field("array", t("system/hash"))
        .build()
}

fn compute_numeric_cast() -> TypeDefinition {
    TypeDefBuilder::new("compute/numeric-cast")
        .field("value", t("system/hash"))
        .field("to_type", t("system/type/name"))
        .build()
}

// EXTENSION-COMPUTE v3.14 N.2 — args types for collection builtins (§3.5).
fn system_compute_map_args() -> TypeDefinition {
    TypeDefBuilder::new("system/compute/map-args")
        .field("collection", t("system/hash"))
        .field("fn", t("system/hash"))
        .build()
}

fn system_compute_filter_args() -> TypeDefinition {
    TypeDefBuilder::new("system/compute/filter-args")
        .field("collection", t("system/hash"))
        .field("fn", t("system/hash"))
        .build()
}

fn system_compute_fold_args() -> TypeDefinition {
    TypeDefBuilder::new("system/compute/fold-args")
        .field("collection", t("system/hash"))
        .field("fn", t("system/hash"))
        .field("initial", t("system/hash"))
        .build()
}

// ============================================================================
// Attestation substrate — EXTENSION-ATTESTATION v1.0 §3.1
// ============================================================================

fn system_attestation() -> TypeDefinition {
    TypeDefBuilder::new("system/attestation")
        .field("attesting", t("system/hash"))
        .field("attested", t("system/hash"))
        .field("properties", map(t("primitive/any")))
        .field("supersedes", opt("system/hash"))
        .field("not_before", opt("primitive/uint"))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

// ----------------------------------------------------------------------------
// Attestation handler op request/result types — per spec v1.1 §6
// (Naming convention per V7 precedent; logged at SPEC-AMBIGUITIES SPEC-24.)
// ----------------------------------------------------------------------------

fn system_attestation_create_request() -> TypeDefinition {
    // §6.1: {attesting, attested, properties, supersedes?, not_before?, expires_at?}
    TypeDefBuilder::new("system/attestation/create-request")
        .field("attesting", t("system/hash"))
        .field("attested", t("system/hash"))
        .field("properties", map(t("primitive/any")))
        .field("supersedes", opt("system/hash"))
        .field("not_before", opt("primitive/uint"))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

fn system_attestation_create_result() -> TypeDefinition {
    // §6.1: {attestation_hash}
    TypeDefBuilder::new("system/attestation/create-result")
        .field("attestation_hash", t("system/hash"))
        .build()
}

fn system_attestation_supersede_request() -> TypeDefinition {
    // §6.2: {previous_hash, properties, expires_at?, ...}
    TypeDefBuilder::new("system/attestation/supersede-request")
        .field("previous_hash", t("system/hash"))
        .field("properties", opt_map(t("primitive/any")))
        .field("not_before", opt("primitive/uint"))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

fn system_attestation_supersede_result() -> TypeDefinition {
    // §6.2: {attestation_hash}
    TypeDefBuilder::new("system/attestation/supersede-result")
        .field("attestation_hash", t("system/hash"))
        .build()
}

fn system_attestation_revoke_request() -> TypeDefinition {
    // §6.3: {target_hash, reason?, attesting}
    TypeDefBuilder::new("system/attestation/revoke-request")
        .field("target_hash", t("system/hash"))
        .field("attesting", t("system/hash"))
        .field("reason", opt("primitive/string"))
        .build()
}

fn system_attestation_revoke_result() -> TypeDefinition {
    // §6.3: {revocation_hash}
    TypeDefBuilder::new("system/attestation/revoke-result")
        .field("revocation_hash", t("system/hash"))
        .build()
}

fn system_attestation_verify_request() -> TypeDefinition {
    // §6.4: {attestation_hash, as_of?}
    TypeDefBuilder::new("system/attestation/verify-request")
        .field("attestation_hash", t("system/hash"))
        .field("as_of", opt("primitive/uint"))
        .build()
}

fn system_attestation_verify_result() -> TypeDefinition {
    // §6.4: {valid: bool, reason?: string}
    TypeDefBuilder::new("system/attestation/verify-result")
        .field("valid", t("primitive/bool"))
        .field("reason", opt("primitive/string"))
        .build()
}

// ============================================================================
// Quorum substrate — EXTENSION-QUORUM v1.0 §3.1
// ============================================================================

fn system_quorum() -> TypeDefinition {
    TypeDefBuilder::new("system/quorum")
        .field("signers", arr(t("system/hash")))
        .field("threshold", t("primitive/uint"))
        .field("signer_resolution", opt("primitive/string"))
        .field("name", opt("primitive/string"))
        .field(
            "metadata",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .build()
}

// ----------------------------------------------------------------------------
// Quorum handler op request/result types — per spec v1.1 §6
// ----------------------------------------------------------------------------

fn system_quorum_create_request() -> TypeDefinition {
    // §6.1: {signers, threshold, signer_resolution?, name?, metadata?}
    TypeDefBuilder::new("system/quorum/create-request")
        .field("signers", arr(t("system/hash")))
        .field("threshold", t("primitive/uint"))
        .field("signer_resolution", opt("primitive/string"))
        .field("name", opt("primitive/string"))
        .field(
            "metadata",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .build()
}

fn system_quorum_create_result() -> TypeDefinition {
    // §6.1: {quorum_id}
    TypeDefBuilder::new("system/quorum/create-result")
        .field("quorum_id", t("system/hash"))
        .build()
}

fn system_quorum_update_request() -> TypeDefinition {
    // §6.2: {quorum_id, new_signers, new_threshold, supersedes?}
    TypeDefBuilder::new("system/quorum/update-request")
        .field("quorum_id", t("system/hash"))
        .field("new_signers", arr(t("system/hash")))
        .field("new_threshold", t("primitive/uint"))
        .field("supersedes", opt("system/hash"))
        .build()
}

fn system_quorum_update_result() -> TypeDefinition {
    // §6.2: {update_hash}
    TypeDefBuilder::new("system/quorum/update-result")
        .field("update_hash", t("system/hash"))
        .build()
}

fn system_quorum_publish_request() -> TypeDefinition {
    // §6.3: {quorum_id, signers, threshold, published_handle?, properties?, supersedes?}
    TypeDefBuilder::new("system/quorum/publish-request")
        .field("quorum_id", t("system/hash"))
        .field("signers", arr(t("system/hash")))
        .field("threshold", t("primitive/uint"))
        .field("published_handle", opt("system/hash"))
        .field("properties", opt_map(t("primitive/any")))
        .field("supersedes", opt("system/hash"))
        .build()
}

fn system_quorum_publish_result() -> TypeDefinition {
    // §6.3: {publish_hash}
    TypeDefBuilder::new("system/quorum/publish-result")
        .field("publish_hash", t("system/hash"))
        .build()
}

fn system_quorum_verify_request() -> TypeDefinition {
    // §6.4: {entity_hash, quorum_id}
    TypeDefBuilder::new("system/quorum/verify-request")
        .field("entity_hash", t("system/hash"))
        .field("quorum_id", t("system/hash"))
        .build()
}

fn system_quorum_verify_result() -> TypeDefinition {
    // §6.4: {valid: bool, signed_by: [hash]}
    TypeDefBuilder::new("system/quorum/verify-result")
        .field("valid", t("primitive/bool"))
        .field("signed_by", arr(t("system/hash")))
        .build()
}

// ============================================================================
// Identity types — EXTENSION-IDENTITY v3.2
// (substrate primitives `system/quorum` + `system/attestation` live in
// EXTENSION-QUORUM and EXTENSION-ATTESTATION; identity owns only
// peer-config + identity-binding helper inner type.)
// ============================================================================

fn system_identity_peer_config() -> TypeDefinition {
    TypeDefBuilder::new("system/identity/peer-config")
        .field("trusts_quorum", t("system/hash"))
        .field("controller_grants", arr(t("system/capability/grant-entry")))
        .field("bindings", opt_arr(t("system/identity/identity-binding")))
        .field(
            "metadata",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .build()
}

fn system_identity_identity_binding() -> TypeDefinition {
    TypeDefBuilder::new("system/identity/identity-binding")
        .field("handle_cert", t("system/hash"))
        .field("agent_cert", t("system/hash"))
        .field("label", opt("primitive/string"))
        .field(
            "metadata",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .build()
}

fn system_identity_configure_request() -> TypeDefinition {
    TypeDefBuilder::new("system/identity/configure-request")
        .field("trusts_quorum", t("system/hash"))
        .field("controller_grants", arr(t("system/capability/grant-entry")))
        .field("bindings", opt_arr(t("system/identity/identity-binding")))
        .build()
}

fn system_identity_configure_result() -> TypeDefinition {
    TypeDefBuilder::new("system/identity/configure-result")
        .field("peer_config_path", t("system/tree/path"))
        .field("local_peer_to_controller_caps", arr(t("system/hash")))
        .build()
}

fn system_identity_create_quorum_request() -> TypeDefinition {
    // Wraps EXTENSION-QUORUM:create. Caller supplies signers + threshold;
    // identity creates the quorum entity and initializes peer-config.
    // Per CROSS-IMPL-ACME-RUST R-4: `name` and `metadata` are
    // structural fields of `system/quorum` and MUST round-trip through
    // the create request so the caller's locally-computed canonical
    // path matches the handler's recomputed path under R-3 strict.
    TypeDefBuilder::new("system/identity/create-quorum-request")
        .field("signers", arr(t("system/hash")))
        .field("threshold", t("primitive/uint"))
        .field("signer_resolution", opt("primitive/string"))
        .field("name", opt("primitive/string"))
        .field(
            "metadata",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .build()
}

fn system_identity_create_attestation_request() -> TypeDefinition {
    // Wraps EXTENSION-ATTESTATION §6.1 + EXTENSION-IDENTITY §6.
    // Per CROSS-IMPL-ACME-RUST R-1: `properties` MUST be a
    // single map field; `kind` / `function` / `mode` / `contact_id` /
    // `target_cert` / `old_handle` are NESTED inside that map, not flat
    // top-level fields. The substrate `system/attestation:create`
    // shape uses `properties: map`; the identity wrapper mirrors it.
    TypeDefBuilder::new("system/identity/create-attestation-request")
        .field("attesting", t("system/hash"))
        .field("attested", t("system/hash"))
        .field(
            "properties",
            FieldSpec::map(FieldSpec::type_ref("primitive/any"), None),
        )
        .field("supersedes", opt("system/hash"))
        .field("not_before", opt("primitive/uint"))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

fn system_identity_create_attestation_result() -> TypeDefinition {
    // Per CROSS-IMPL-ACME-RUST R-6: two distinct shapes —
    // (a) regular modes return {attestation_hash, storage_path?}, and
    // (b) embedded mode returns {embedded_attestation: <inline AttestationData>}
    //     with `attestation_hash` absent (Go uses cbor:"omitempty" with zero hash).
    // The fields are therefore all optional; the consumer routes on which
    // is present. The handler emits exactly one shape per call.
    TypeDefBuilder::new("system/identity/create-attestation-result")
        .field("attestation_hash", opt("system/hash"))
        .field("storage_path", opt("system/tree/path"))
        .field(
            "embedded_attestation",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .build()
}

fn system_identity_supersede_attestation_request() -> TypeDefinition {
    // Per EXTENSION-ATTESTATION §6.1 / §6.2 wire-shape (R-8 alignment with
    // Go's reference impl): supersede uses the same flat AttestationData
    // shape as `:create`, with `supersedes` set to the previous attestation
    // hash. `attesting`/`attested` MUST match the predecessor's (§6.2). The
    // §6.2 pseudo-shape's `previous_hash` field name was inconsistent with
    // §6.1's `supersedes` field on the AttestationData; Go and Rust align
    // on §6.1.
    TypeDefBuilder::new("system/identity/supersede-attestation-request")
        .field("attesting", t("system/hash"))
        .field("attested", t("system/hash"))
        .field("supersedes", t("system/hash"))
        .field(
            "properties",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .field("not_before", opt("primitive/uint"))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

fn system_identity_publish_attestation_request() -> TypeDefinition {
    TypeDefBuilder::new("system/identity/publish-attestation-request")
        .field("attestation_hash", t("system/hash"))
        .field("new_mode", t("primitive/string"))
        .field("contact_id", opt("system/hash"))
        .build()
}

// ----------------------------------------------------------------------------
// Identity result types — per spec v3.3 §6 / §14.3
// (5 missing per the cross-impl validator; result shapes match the
// handler's HandlerResult content fields.)
// ----------------------------------------------------------------------------

fn system_identity_create_quorum_result() -> TypeDefinition {
    // create_quorum delegates to QUORUM:create — returns {quorum_id}.
    TypeDefBuilder::new("system/identity/create-quorum-result")
        .field("quorum_id", t("system/hash"))
        .build()
}

fn system_identity_supersede_attestation_result() -> TypeDefinition {
    // Supersede returns {attestation_hash, storage_path?}.
    TypeDefBuilder::new("system/identity/supersede-attestation-result")
        .field("attestation_hash", t("system/hash"))
        .field("storage_path", opt("system/tree/path"))
        .build()
}

fn system_identity_revoke_attestation_request() -> TypeDefinition {
    // Per §6 / §14.3: resource = attestation's stored path; no other params.
    TypeDefBuilder::new("system/identity/revoke-attestation-request").build()
}

fn system_identity_revoke_attestation_result() -> TypeDefinition {
    // Per CROSS-IMPL-ACME-RUST R-12' (Round-8) +
    // Go's `core/types/identity.go::IdentityRevokeAttestationResultData`:
    // result carries `revocation_hash` — the content_hash of the
    // newly-minted revocation attestation. Pre-R-12' Rust used an empty
    // payload (matching a stub revoke handler); Round-7 R-12 rewrote
    // revoke to actually mint a revocation entity, so the result now
    // has a meaningful hash to return.
    TypeDefBuilder::new("system/identity/revoke-attestation-result")
        .field("revocation_hash", t("system/hash"))
        .build()
}

fn system_identity_publish_attestation_result() -> TypeDefinition {
    // Per CROSS-IMPL-ACME-RUST R-9: destination-path field is
    // `new_path` (matches Go's `IdentityPublishAttestationResultData.NewPath`).
    // Returns {attestation_hash, new_path}.
    TypeDefBuilder::new("system/identity/publish-attestation-result")
        .field("attestation_hash", t("system/hash"))
        .field("new_path", t("system/tree/path"))
        .build()
}

/// PI-5 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-5, Rev 3): controller-
/// events stream entity. Failure-observation + recovery-signal events
/// emitted from `:process_attestation` Phase 2 handlers and from
/// `:publish_attestation` orphan-binding recovery (PI-3).
fn system_identity_event() -> TypeDefinition {
    TypeDefBuilder::new("system/identity/event")
        .field("event_subkind", t("primitive/string"))
        .field("handler_id", t("primitive/string"))
        .field("attestation_hash", t("system/hash"))
        .field("attestation_kind", t("primitive/string"))
        .field("error_code", t("primitive/string"))
        .field("error_detail", t("primitive/string"))
        .field("timestamp_ms", t("primitive/uint"))
        .build()
}

// ============================================================================
// Role types — EXTENSION-ROLE v1.5 §2 + §4.2
// (3 entity types + 9 op request/result types; `unassign`/`unexclude` use
// the empty-params shape per V7 §3.2 path-as-resource, so they need no
// dedicated request types.)
// ============================================================================

fn system_role() -> TypeDefinition {
    // §2.1: {name, grants[], metadata?}
    TypeDefBuilder::new("system/role")
        .field("name", t("primitive/string"))
        .field("grants", arr(t("system/capability/grant-entry")))
        .field(
            "metadata",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .build()
}

fn system_role_assignment() -> TypeDefinition {
    // §2.2: {role, assigned_by, assigned_at, metadata?}
    TypeDefBuilder::new("system/role/assignment")
        .field("role", t("primitive/string"))
        .field("assigned_by", t("system/hash"))
        .field("assigned_at", t("primitive/uint"))
        .field(
            "metadata",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .build()
}

fn system_role_exclusion() -> TypeDefinition {
    // §2.3 v1.6 (SI-3): peer_id field dropped — redundant with the
    // hex-encoded path segment {peer_id_hex} after SI-1.
    // {excluded_by, excluded_at, reason?}
    TypeDefBuilder::new("system/role/exclusion")
        .field("excluded_by", t("system/hash"))
        .field("excluded_at", t("primitive/uint"))
        .field("reason", opt("primitive/string"))
        .build()
}

fn system_role_derived_token_link() -> TypeDefinition {
    // §2.4 v1.6 (SI-5): per-(peer, role, context) linkage entity.
    // Stored at system/role/{context}/derived-tokens/{peer_id_hex}/{role_name}.
    // Maps an assignment to the role-derived cap content_hash so unassign
    // and delegation parent-selection can locate the cap deterministically.
    TypeDefBuilder::new("system/role/derived-token-link")
        .field("token_hash", t("system/hash"))
        .field("issued_at", t("primitive/uint"))
        .build()
}

fn system_role_define_request() -> TypeDefinition {
    // §4.2: {grants[], metadata?} — resource is the role-definition path.
    TypeDefBuilder::new("system/role/define-request")
        .field("grants", arr(t("system/capability/grant-entry")))
        .field(
            "metadata",
            FieldSpec::optional_map(FieldSpec::type_ref("primitive/any"), None),
        )
        .build()
}

fn system_role_define_result() -> TypeDefinition {
    // §4.2: {role_path, re_derived_count?}
    TypeDefBuilder::new("system/role/define-result")
        .field("role_path", t("system/tree/path"))
        .field("re_derived_count", opt("primitive/uint"))
        .build()
}

fn system_role_assign_request() -> TypeDefinition {
    // §4.2: {role} — resource is the assignment path.
    TypeDefBuilder::new("system/role/assign-request")
        .field("role", t("primitive/string"))
        .build()
}

fn system_role_assign_result() -> TypeDefinition {
    // §4.2: {assignment_path, derived_tokens?}
    TypeDefBuilder::new("system/role/assign-result")
        .field("assignment_path", t("system/tree/path"))
        .field("derived_tokens", opt_arr(t("system/hash")))
        .build()
}

fn system_role_exclude_result() -> TypeDefinition {
    // §4.2 (SI-9): {exclusion_path, revoked_token_hashes?}.
    TypeDefBuilder::new("system/role/exclude-result")
        .field("exclusion_path", t("system/tree/path"))
        .field("revoked_token_hashes", opt_arr(t("system/hash")))
        .build()
}

fn system_role_unassign_result() -> TypeDefinition {
    // v1.6 cross-impl alignment with Go reference:
    // {assignment_path, revoked_token_hashes?}. The empty-result form
    // (system/protocol/status) was a v1.5 simplification; v1.6 mirrors
    // exclude-result's pattern.
    TypeDefBuilder::new("system/role/unassign-result")
        .field("assignment_path", t("system/tree/path"))
        .field("revoked_token_hashes", opt_arr(t("system/hash")))
        .build()
}

fn system_role_unexclude_result() -> TypeDefinition {
    // v1.6 cross-impl alignment with Go reference: {exclusion_path}.
    TypeDefBuilder::new("system/role/unexclude-result")
        .field("exclusion_path", t("system/tree/path"))
        .build()
}

fn system_role_re_derive_request() -> TypeDefinition {
    // §4.2: {role} — resource is the role-definition path.
    TypeDefBuilder::new("system/role/re-derive-request")
        .field("role", t("primitive/string"))
        .build()
}

fn system_role_re_derive_result() -> TypeDefinition {
    // §4.2 v1.6 (SI-15): adds skipped_grantees for RL2-failure-mid-cascade
    // skip-and-continue semantics. Type uniformity: all three arrays are
    // array_of system/hash.
    TypeDefBuilder::new("system/role/re-derive-result")
        .field("re_derived_count", t("primitive/uint"))
        .field("revoked_token_hashes", opt_arr(t("system/hash")))
        .field("new_token_hashes", opt_arr(t("system/hash")))
        .field("skipped_grantees", opt_arr(t("system/hash")))
        .build()
}

fn system_role_delegate_request() -> TypeDefinition {
    // §4.2 v1.6 (SI-4 + SI-21): context/role are primitive/string (matches
    // assign-request); delegator field dropped (caller is implicit from
    // ctx.execute.data.author per SI-21).
    TypeDefBuilder::new("system/role/delegate-request")
        .field("delegate", t("system/hash"))
        .field("context", t("primitive/string"))
        .field("role", t("primitive/string"))
        .field("scope", arr(t("system/capability/grant-entry")))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

fn system_role_delegate_result() -> TypeDefinition {
    // §4.2: {delegation_token_hash}
    TypeDefBuilder::new("system/role/delegate-result")
        .field("delegation_token_hash", t("system/hash"))
        .build()
}

fn system_role_initial_grant_policy() -> TypeDefinition {
    // EXTENSION-ROLE §4.7 (recognize-on-attestation handoff §3).
    // Singleton at `system/role/initial-grant-policy` — drives the
    // connect-handler's grant resolver at AUTHENTICATE.
    //   unknown_peer      string  (REQUIRED)
    //   default_role      string  (omitempty)
    //   default_context   string  (omitempty)
    //   identity_required bool    (omitempty)
    TypeDefBuilder::new("system/role/initial-grant-policy")
        .field("unknown_peer", t("primitive/string"))
        .field("default_role", opt("primitive/string"))
        .field("default_context", opt("primitive/string"))
        .field("identity_required", opt("primitive/bool"))
        .build()
}

// ============================================================================
// Public API
// ============================================================================

/// Returns all core type definitions per spec §11.2.
pub fn all_core_types() -> Vec<TypeDefinition> {
    vec![
        // Bootstrap: 8 primitives
        primitive_string(),
        primitive_bytes(),
        primitive_uint(),
        primitive_int(),
        primitive_float(),
        primitive_bool(),
        primitive_null(),
        primitive_any(),
        // Bootstrap: meta-types (3)
        system_hash(),
        system_type(),
        system_type_field_spec(),
        // Semantic types (3) + deletion-marker (NATIVE-TYPE-SYSTEM v4.2.0)
        system_tree_path(),
        system_type_name(),
        system_peer_id(),
        system_deletion_marker(),
        // Bootstrap: structural root (2-field {type, data}; content_hash derived)
        entity_type(),
        // Core types (2): materialized form + envelope
        core_entity(),
        core_envelope(),
        // Protocol types
        system_protocol_envelope(),
        system_protocol_connect_hello(),
        system_protocol_connect_authenticate(),
        system_protocol_execute(),
        system_protocol_execute_response(),
        system_protocol_error(),
        // Capability types
        system_capability_path_scope(),
        system_capability_id_scope(),
        system_capability_grant_entry(),
        system_capability_delegation_caveats(),
        system_capability_token(),
        system_capability_multi_granter(),
        system_capability_request(),
        system_capability_revocation(),
        system_capability_revoke_request(),
        system_capability_delegate_request(),
        system_capability_policy_entry(),
        system_capability_grant(),
        // Supporting types
        system_peer(),
        system_peer_self_status(),
        system_peer_published_root(),
        system_signature(),
        system_handler(),
        system_handler_manifest(),
        system_handler_operation_spec(),
        system_handler_interface(),
        system_bounds(),
        system_resource_limits(),
        // Protocol resource target
        system_protocol_resource_target(),
        // Handler registration
        system_handler_register_request(),
        system_handler_register_result(),
        // unregister-request eliminated by PROPOSAL-PATH-AS-RESOURCE-HYGIENE.
        // Tree types
        system_tree_listing_entry(),
        system_tree_listing(),
        system_tree_get_request(),
        system_tree_put_request(),
        system_tree_put_result(),
        system_tree_snapshot_request(),
        system_tree_snapshot(),
        system_tree_diff_request(),
        system_tree_diff_change(),
        system_tree_diff(),
        system_tree_merge_request(),
        system_tree_merge_conflict(),
        system_tree_merge_result(),
        system_tree_extract_request(),
        system_tree_tracking_config(),
        // Content (EXTENSION-CONTENT v3.5)
        system_content_blob(),
        system_content_chunk(),
        system_content_descriptor(),
        system_content_get_request(),
        system_content_content_response(),
        system_content_ingest_request(),
        system_content_ingest_result(),
        // Validation (EXTENSION-TYPE v1.1)
        system_type_validate_request(),
        system_type_validate_result(),
        system_type_violation(),
        // EXTENSION-TYPE v1.1 — constraint dispatch envelope types
        system_type_constraint_validate_request(),
        system_type_constraint_validate_result(),
        // EXTENSION-TYPE v1.1 — 11 standard constraint types (§4)
        system_type_constraint_min(),
        system_type_constraint_max(),
        system_type_constraint_min_length(),
        system_type_constraint_max_length(),
        system_type_constraint_min_count(),
        system_type_constraint_max_count(),
        system_type_constraint_pattern(),
        system_type_constraint_one_of(),
        system_type_constraint_not_one_of(),
        system_type_constraint_format(),
        system_type_constraint_type_pattern(),
        // EXTENSION-TYPE v1.1 — analysis-op support types (§7, §8)
        system_type_field_comparison(),
        system_type_field_incompatibility(),
        system_type_compare_request(),
        system_type_compare_result(),
        system_type_compatible_request(),
        system_type_compatibility_report(),
        // Delivery
        system_delivery_spec(),
        // Durability contract (EXTENSION-DURABILITY v0.1, exploratory)
        system_durability_request(),
        system_durability_result(),
        system_durability_advertisement(),
        // Subscription extension
        system_subscription(),
        system_subscription_request(),
        system_subscription_cancel(),
        system_subscription_limits(),
        system_subscription_redirect(),
        system_config_subscription(),
        // Inbox extension
        system_inbox_delivery(),
        system_inbox_notification(),
        // Continuation extension
        system_continuation(),
        system_continuation_transform(),
        system_continuation_transform_op(),
        system_continuation_join(),
        system_continuation_suspended(),
        system_continuation_advance_request(),
        system_continuation_resume_request(),
        system_continuation_abandon_request(),
        system_continuation_advance_result(),
        system_continuation_install_result(),
        // Clock extension (9 types)
        system_clock_timestamp(),
        system_clock_logical(),
        system_clock_vector(),
        system_clock_hlc(),
        system_clock_config(),
        system_clock_state(),
        system_clock_compare_params(),
        system_clock_compare_result(),
        system_clock_tick(),
        // Tree snapshot node (trie)
        system_tree_snapshot_node(),
        // Revision extension (12 types)
        system_revision_entry(),
        system_revision_conflict(),
        system_revision_config_params(),
        system_revision_config_result(),
        system_revision_cascade_warning(),
        system_revision_commit_params(),
        system_revision_commit_result(),
        system_revision_merge_result(),
        system_revision_checkout_result(),
        system_revision_cherry_pick_result(),
        system_revision_revert_result(),
        system_revision_branch_result(),
        // Query extension (5 types)
        system_query_expression(),
        system_query_result(),
        system_query_match(),
        system_query_field_predicate(),
        system_query_constraints(),
        system_query_allowances(),
        system_query_index_config(),
        // History extension (6 types)
        system_history_transition(),
        system_history_config(),
        system_history_query_params(),
        system_history_query_result(),
        system_history_rollback_params(),
        system_history_rollback_result(),
        // Envelope
        system_envelope(),
        // Compute extension (21 types)
        compute_literal(),
        compute_lookup_scope(),
        compute_lookup_tree(),
        compute_apply(),
        compute_if(),
        compute_let(),
        compute_lambda(),
        compute_arithmetic(),
        compute_compare(),
        compute_logic(),
        compute_field(),
        compute_construct(),
        compute_lookup_hash(),
        compute_closure(),
        compute_scope(),
        system_compute_scope_binding(),
        compute_result(),
        compute_error(),
        system_compute_subgraph(),
        system_compute_install_request(),
        system_compute_install_result(),
        // uninstall-request eliminated by PROPOSAL-PATH-AS-RESOURCE-HYGIENE.
        system_compute_store_args(),
        // EXTENSION-COMPUTE v3.14 N.1 — new inline expression types.
        compute_index(),
        compute_length(),
        compute_numeric_cast(),
        // EXTENSION-COMPUTE v3.14 N.2 — collection builtin args types.
        system_compute_map_args(),
        system_compute_filter_args(),
        system_compute_fold_args(),
        // Attestation substrate (EXTENSION-ATTESTATION v1.1 — 1 entity + 8 op types)
        system_attestation(),
        system_attestation_create_request(),
        system_attestation_create_result(),
        system_attestation_supersede_request(),
        system_attestation_supersede_result(),
        system_attestation_revoke_request(),
        system_attestation_revoke_result(),
        system_attestation_verify_request(),
        system_attestation_verify_result(),
        // Quorum substrate (EXTENSION-QUORUM v1.1 — 1 entity + 8 op types)
        system_quorum(),
        system_quorum_create_request(),
        system_quorum_create_result(),
        system_quorum_update_request(),
        system_quorum_update_result(),
        system_quorum_publish_request(),
        system_quorum_publish_result(),
        system_quorum_verify_request(),
        system_quorum_verify_result(),
        // Identity extension (EXTENSION-IDENTITY v3.3 — 2 owned + 12 op types)
        // (system/quorum + system/attestation moved to substrate primitives.)
        system_identity_peer_config(),
        system_identity_identity_binding(),
        system_identity_configure_request(),
        system_identity_configure_result(),
        system_identity_create_quorum_request(),
        system_identity_create_quorum_result(),
        system_identity_create_attestation_request(),
        system_identity_create_attestation_result(),
        system_identity_supersede_attestation_request(),
        system_identity_supersede_attestation_result(),
        system_identity_revoke_attestation_request(),
        system_identity_revoke_attestation_result(),
        system_identity_publish_attestation_request(),
        system_identity_publish_attestation_result(),
        system_identity_event(),
        // Role extension (EXTENSION-ROLE v1.6 — 4 entity + 9 op types;
        // derived-token-link added per SI-5)
        system_role(),
        system_role_assignment(),
        system_role_exclusion(),
        system_role_derived_token_link(),
        system_role_define_request(),
        system_role_define_result(),
        system_role_assign_request(),
        system_role_assign_result(),
        system_role_unassign_result(),
        system_role_exclude_result(),
        system_role_unexclude_result(),
        system_role_re_derive_request(),
        system_role_re_derive_result(),
        system_role_delegate_request(),
        system_role_delegate_result(),
        system_role_initial_grant_policy(),
        // Transport profile (EXTENSION-NETWORK §6.5.3 — http-poll)
        system_peer_transport_http_poll(),
        // Storage-substitute family (RULINGS-STORAGE-SUBSTITUTE)
        system_substitute_endpoint(),
        system_substitute_source(),
        system_substitute_try_request(),
        system_substitute_snapshot_manifest(),
        // Registry (EXTENSION-REGISTRY v1.0 — substrate + local-name)
        system_registry_binding(),
        system_registry_revocation(),
        system_registry_resolver_config(),
        system_registry_local_name_config(),
        system_registry_resolution_log(),
        // Registry F1 — resolution + local-name op types
        system_registry_resolver_chain_entry(),
        system_registry_pinned_entry(),
        system_registry_dispatch_entry(),
        system_registry_resolve_request(),
        system_registry_resolution_result(),
        system_registry_invalidate_cache_request(),
        system_registry_local_name_bind_request(),
        system_registry_local_name_bind_result(),
        system_registry_local_name_unbind_request(),
        system_registry_local_name_list_request(),
        system_registry_local_name_list_entry(),
        system_registry_local_name_list_result(),
        system_registry_local_name_update_transports_request(),
        // Peer-issued live registration (EXTENSION-REGISTRY §6a.9)
        system_registry_register_request(),
        system_registry_register_result(),
        system_registry_issuer_policy(),
        system_registry_revoke_request(),
        system_registry_renew_request(),
        // Discovery (EXTENSION-DISCOVERY v1.0)
        system_discovery_announce_request(),
        system_discovery_announce_stop_request(),
        system_discovery_candidate(),
        system_discovery_decision(),
        system_discovery_identity_claim(),
        system_discovery_scan_request(),
        system_discovery_scan_result(),
        // Relay (EXTENSION-RELAY v1.0)
        system_relay_advertise_limits(),
        system_relay_advertise(),
        system_relay_forward_request(),
        system_relay_forward_result(),
        system_relay_poll_request(),
        system_relay_poll_result(),
        system_relay_put_result(),
        system_relay_store_entry(),
        // Route (EXTENSION-ROUTE v1.0)
        system_route(),
        // Peer inbox-relay (EXTENSION-RELAY v1.0 §3.5)
        system_peer_inbox_relay_entry(),
        system_peer_inbox_relay(),
        // Encryption (EXTENSION-ENCRYPTION v1.0 — 5 entity + 2 sub-shape types,
        // R4-blessed names; + system/note R3 KAT carrier). Sub-shapes first so
        // the system/encrypted nested type-refs resolve.
        system_encryption_kdf_params(),
        system_encryption_wrapped_key(),
        system_encryption_pubkey(),
        system_encrypted(),
        system_encryption_handoff(),
        system_encryption_revocation(),
        system_encryption_key_backup(),
        system_note(),
        // Type adopt/converge/reconcile (EXTENSION-TYPE §7.4-7.6)
        system_type_adopt_request(),
        system_type_converge_request(),
        system_type_reconcile_request(),
        system_type_reconcile_result(),
    ]
}

// ---------------------------------------------------------------------------
// Query extension types
// ---------------------------------------------------------------------------

fn system_query_expression() -> TypeDefinition {
    TypeDefBuilder::new("system/query/expression")
        .field("type_filter", opt("primitive/string"))
        .field("field_filters", FieldSpec::optional_array(FieldSpec::type_ref("system/query/field-predicate")))
        .field("ref_filter", opt("system/hash"))
        .field("path_filter", opt("system/tree/path"))
        .field("path_prefix", opt("system/tree/path"))
        .field("limit", opt("primitive/uint"))
        .field("cursor", opt("primitive/string"))
        .field("order_by", opt("primitive/string"))
        .field("descending", opt("primitive/bool"))
        .field("include_entities", opt("primitive/bool"))
        .build()
}

fn system_query_result() -> TypeDefinition {
    TypeDefBuilder::new("system/query/result")
        .field("matches", FieldSpec::array(FieldSpec::type_ref("system/query/match")))
        .field("total", t("primitive/uint"))
        .field("has_more", t("primitive/bool"))
        .field("cursor", opt("primitive/string"))
        .build()
}

fn system_query_match() -> TypeDefinition {
    TypeDefBuilder::new("system/query/match")
        .field("path", opt("system/tree/path"))
        .field("hash", t("system/hash"))
        .field("type", t("system/type/name"))
        .build()
}

fn system_query_field_predicate() -> TypeDefinition {
    TypeDefBuilder::new("system/query/field-predicate")
        .field("field", t("primitive/string"))
        .field("operator", t("primitive/string"))
        .field("value", opt("primitive/any"))
        .build()
}

fn system_query_constraints() -> TypeDefinition {
    TypeDefBuilder::new("system/query/constraints")
        .field("max_results", opt("primitive/uint"))
        .field("type_scope", opt("system/capability/id-scope"))
        .build()
}

fn system_query_allowances() -> TypeDefinition {
    TypeDefBuilder::new("system/query/allowances")
        .field("scope", opt("primitive/string"))
        .build()
}

fn system_query_index_config() -> TypeDefinition {
    TypeDefBuilder::new("system/query/index-config")
        .field("type_name", t("system/type/name"))
        .field("fields", FieldSpec::array(FieldSpec::type_ref("primitive/string")))
        .build()
}

// ---------------------------------------------------------------------------
// History extension types
// ---------------------------------------------------------------------------

fn system_history_transition() -> TypeDefinition {
    TypeDefBuilder::new("system/history/transition")
        .field("path", t("system/tree/path"))
        .field("event", t("primitive/string"))
        .field("hash", opt("system/hash"))
        .field("previous_hash", opt("system/hash"))
        .field("author", t("system/hash"))
        .field("capability", t("system/hash"))
        .field("caller_capability", opt("system/hash"))
        .field("handler", t("system/tree/path"))
        .field("operation", t("primitive/string"))
        .field("timestamp", t("primitive/uint"))
        .field("chain_id", opt("primitive/string"))
        .field("parent_chain_id", opt("primitive/string"))
        .field("clock", opt("system/clock/state"))
        .field("previous", opt("system/hash"))
        .build()
}

fn system_history_config() -> TypeDefinition {
    TypeDefBuilder::new("system/history/config")
        .field("pattern", t("system/tree/path"))
        .field("enabled", t("primitive/bool"))
        .field("events", opt_arr(t("primitive/string")))
        .field("max_depth", opt("primitive/uint"))
        .build()
}

fn system_history_query_params() -> TypeDefinition {
    TypeDefBuilder::new("system/history/query-params")
        .field("path", t("system/tree/path"))
        .field("limit", opt("primitive/uint"))
        .field("since", opt("system/hash"))
        .field("before", opt("primitive/uint"))
        .field("events", opt_arr(t("primitive/string")))
        .build()
}

fn system_history_query_result() -> TypeDefinition {
    TypeDefBuilder::new("system/history/query-result")
        .field("path", t("system/tree/path"))
        .field("head", opt("system/hash"))
        .field("transitions", arr(t("system/history/transition")))
        .field("has_more", t("primitive/bool"))
        .build()
}

fn system_history_rollback_params() -> TypeDefinition {
    TypeDefBuilder::new("system/history/rollback-params")
        .field("path", t("system/tree/path"))
        .field("target_hash", t("system/hash"))
        .build()
}

fn system_history_rollback_result() -> TypeDefinition {
    TypeDefBuilder::new("system/history/rollback-result")
        .field("path", t("system/tree/path"))
        .field("restored", t("system/hash"))
        .build()
}

fn system_envelope() -> TypeDefinition {
    TypeDefBuilder::new("system/envelope")
        .extends("core/envelope")
        .build()
}

// ============================================================================
// EXTENSION-NETWORK §6.5.3 — http-poll transport profile.
// `peer_id` is the Base58 id `system/peer-id` per NETWORK errata `bdfb545`
// (cross-impl F1) — it matches the {peer_id} path segment, not a content
// hash. `endpoint` is the shared `system/substitute/endpoint` shape. Optional
// fields follow Go's reflect registration (omitempty): freshness, cap_flow,
// poll_interval_ms, signed_pointer, advertised_at (Q6), priority (Q1).
// ============================================================================

fn system_peer_transport_http_poll() -> TypeDefinition {
    TypeDefBuilder::new("system/peer/transport/http-poll")
        .field("peer_id", t("system/peer-id"))
        .field("transport_type", t("primitive/string"))
        .field("endpoint", t("system/substitute/endpoint"))
        .field("supported_ops", arr(t("primitive/string")))
        .field("freshness", opt("primitive/string"))
        .field("nonce_required", t("primitive/bool"))
        .field("cap_flow", opt("primitive/string"))
        .field("poll_interval_ms", opt("primitive/uint"))
        .field("signed_pointer", opt("primitive/string"))
        .field("advertised_at", opt("primitive/uint"))
        .field("priority", opt("primitive/uint"))
        .build()
}

// ============================================================================
// EXTENSION-STORAGE-SUBSTITUTE family. Wire shapes pinned by
// RULINGS-STORAGE-SUBSTITUTE-CROSS-IMPL (R1/R2) over
// PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-{HTTP,SOURCES}. (Still proposal-stage;
// see docs/SPEC-AMBIGUITIES.md — registered to the ruled shapes the cohort
// converged on.)
// ============================================================================

fn system_substitute_endpoint() -> TypeDefinition {
    TypeDefBuilder::new("system/substitute/endpoint")
        .field("tree_url_prefix", t("primitive/string"))
        .field("content_url_prefix", t("primitive/string"))
        // EXTENSION-NETWORK §6.5.3 Amendment 5 — singular signed-manifest
        // prefix (terminal, no suffix).
        .field("manifest_url_prefix", opt("primitive/string"))
        .field("content_layout", t("primitive/string"))
        .field("tree_leaf_suffix", opt("primitive/string"))
        // EXTENSION-NETWORK §6.5.3 Amendment 5 — listing-object suffix
        // (default ".list"; distinct from tree_leaf_suffix).
        .field("tree_listing_suffix", opt("primitive/string"))
        .build()
}

fn system_substitute_source() -> TypeDefinition {
    // `priority` is primitive/int (SOURCES §2.1: ascending, lower = consulted
    // first). `source_peer_id` is system/hash — a substrate trust-anchor
    // reference (§1.4), NOT the Base58 id (contrast http-poll.peer_id).
    TypeDefBuilder::new("system/substitute/source")
        .field("name", t("primitive/string"))
        .field("substitute_type", t("primitive/string"))
        .field("source_peer_id", t("system/hash"))
        .field("endpoint", opt("primitive/any"))
        .field("fetch_template", opt("primitive/string"))
        .field("priority", t("primitive/int"))
        .field("enabled", t("primitive/bool"))
        .field("expires_at", opt("primitive/uint"))
        .field("supersedes", opt("system/hash"))
        .build()
}

fn system_substitute_try_request() -> TypeDefinition {
    // `entry` carries the full source entity per Ruling 2 (NOT its hash) —
    // the handler needs the source's endpoint/substitute_type to fetch.
    TypeDefBuilder::new("system/substitute/try-request")
        .field("entry", t("system/substitute/source"))
        .field("hash", t("system/hash"))
        .build()
}

fn system_substitute_snapshot_manifest() -> TypeDefinition {
    TypeDefBuilder::new("system/substitute/snapshot-manifest")
        .field("source_peer_id", t("system/hash"))
        .field("snapshot_at", t("primitive/uint"))
        .field("seq", t("primitive/uint"))
        .field("endpoint", t("system/substitute/endpoint"))
        .field("path_index", map(t("system/hash")))
        .field("content_count", t("primitive/uint"))
        .field("root_hashes", arr(t("system/hash")))
        .field("predecessor", opt("system/hash"))
        .build()
}

// ============================================================================
// EXTENSION-REGISTRY v1.0 — substrate binding/revocation/config + local-name.
// `target_peer_id` is the Base58 id `system/peer-id` (V7 §1.5, REGISTRY §3/§4.4
// — an identity, NOT a content-hash). `supersedes` / `issuer_attestation` /
// `revokes` / `binding` are bare `system/hash`. `transports` / `metadata` /
// nested config arrays are opaque CBOR (the substrate passes transports through
// per §6.5; nested config sub-shapes are not separately spec-named). All
// timestamps/durations are ms-since-epoch. The authenticating `system/signature`
// is carried per invariant-pointer (§3), not a `refs:` block.
// ============================================================================

fn system_registry_binding() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/binding")
        .field("name", t("primitive/string"))
        .field("kind", t("primitive/string"))
        .field("target_peer_id", t("system/peer-id"))
        .field("transports", opt_arr(t("system/hash")))
        .field("issued_at", t("primitive/uint"))
        .field("ttl", opt("primitive/uint"))
        .field("supersedes", opt("system/hash"))
        .field("issuer_attestation", opt("system/hash"))
        .field("metadata", opt_map(t("primitive/any")))
        .build()
}

fn system_registry_revocation() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/revocation")
        .field("revokes", t("system/hash"))
        .field("revoked_at", t("primitive/uint"))
        .field("reason", opt("primitive/string"))
        .build()
}

fn system_registry_resolver_config() -> TypeDefinition {
    // Nested arrays carry the named sub-entry types (G3).
    // `resolver_chain` is required (Go reflects it without omitempty); the
    // pinned/dispatch lists are optional.
    TypeDefBuilder::new("system/registry/resolver-config")
        .field(
            "resolver_chain",
            arr(t("system/registry/resolver-chain-entry")),
        )
        .field(
            "pinned_bindings",
            opt_arr(t("system/registry/pinned-entry")),
        )
        .field(
            "name_format_dispatch",
            opt_arr(t("system/registry/dispatch-entry")),
        )
        .field("log_cache_hits", opt("primitive/bool"))
        .field("resolution_log_capacity", opt("primitive/uint"))
        .build()
}

fn system_registry_local_name_config() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/local-name-config")
        .field("default_pinned", t("primitive/bool"))
        .field("allow_supersede", t("primitive/bool"))
        .field("case_normalization", t("primitive/string"))
        .build()
}

fn system_registry_resolution_log() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/resolution-log")
        .field("seq", t("primitive/uint"))
        .field("name", t("primitive/string"))
        .field("backend_id", opt("primitive/string"))
        .field("status", t("primitive/string"))
        .field("reason", opt("primitive/string"))
        .field("binding", opt("system/hash"))
        .field("attempted_at", t("primitive/uint"))
        .field("is_fallback_reresolve", opt("primitive/bool"))
        .build()
}

// ============================================================================
// EXTENSION-REGISTRY v1.0 — resolution + local-name op types (F1).
// Field shapes match the EXTENSION-REGISTRY spec and the Go
// reflected reference (validate-peer oracle). peer-id surfaces use
// system/peer-id; optionality follows Go's omitempty/pointer tags.
// ============================================================================

fn system_registry_resolver_chain_entry() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/resolver-chain-entry")
        .field("backend_kind", t("primitive/string"))
        .field("backend_id", t("primitive/string"))
        .field("priority", t("primitive/uint"))
        .field("accepted_trust_anchors", opt_arr(t("primitive/string")))
        .field("hints", opt_map(t("primitive/any")))
        .build()
}

fn system_registry_pinned_entry() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/pinned-entry")
        .field("name", t("primitive/string"))
        .field("target_peer_id", t("system/peer-id"))
        .field("reason", opt("primitive/string"))
        .build()
}

fn system_registry_dispatch_entry() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/dispatch-entry")
        .field("pattern", t("primitive/string"))
        .field("backend_kinds", arr(t("primitive/string")))
        .build()
}

fn system_registry_resolve_request() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/resolve-request")
        .field("name", t("primitive/string"))
        .field("hints", opt_map(t("primitive/any")))
        .build()
}

fn system_registry_resolution_result() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/resolution-result")
        .field("status", t("primitive/string"))
        .field("binding", opt("system/hash"))
        .field("peer_id", opt("system/peer-id"))
        .field("transports", opt_arr(t("system/hash")))
        .field("attestations", opt_arr(t("system/hash")))
        .field("trust_anchor", opt("primitive/string"))
        .field("ttl", opt("primitive/uint"))
        .field("neg_ttl", opt("primitive/uint"))
        .field("backend_id", opt("primitive/string"))
        .build()
}

fn system_registry_invalidate_cache_request() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/invalidate-cache-request")
        .field("name", opt("primitive/string"))
        .build()
}

fn system_registry_local_name_bind_request() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/local-name/bind-request")
        .field("name", t("primitive/string"))
        .field("target_peer_id", t("system/peer-id"))
        .field("transports", opt_arr(t("system/hash")))
        .field("notes", opt("primitive/string"))
        .build()
}

fn system_registry_local_name_bind_result() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/local-name/bind-result")
        .field("binding_hash", t("system/hash"))
        .build()
}

fn system_registry_local_name_unbind_request() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/local-name/unbind-request")
        .field("name", t("primitive/string"))
        .build()
}

fn system_registry_local_name_list_request() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/local-name/list-request")
        .field("filter", opt_map(t("primitive/any")))
        .build()
}

fn system_registry_local_name_list_entry() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/local-name/list-entry")
        .field("name", t("primitive/string"))
        .field("hash", t("system/hash"))
        .field("target_peer_id", t("system/peer-id"))
        .field("notes", opt("primitive/string"))
        .field("pinned", t("primitive/bool"))
        .build()
}

fn system_registry_local_name_list_result() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/local-name/list-result")
        .field("entries", arr(t("system/registry/local-name/list-entry")))
        .build()
}

fn system_registry_local_name_update_transports_request() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/local-name/update-transports-request")
        .field("name", t("primitive/string"))
        .field("transports", arr(t("system/hash")))
        .build()
}

// ============================================================================
// EXTENSION-REGISTRY §6a.9 — peer-issued live registration. `register-request`
// is the publisher's self-signed claim (layer-1 proof: a system/signature by
// target_peer_id over the request's content_hash); `issuer-policy` is the
// registry-local admission knob (mode + allowlist + name_constraints).
// ============================================================================

fn system_registry_register_request() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/register-request")
        .field("name", t("primitive/string"))
        .field("target_peer_id", t("system/peer-id"))
        .field("transports", opt_arr(t("system/hash")))
        .field("requested_ttl", opt("primitive/uint"))
        .field("nonce", t("primitive/bytes"))
        .field("issued_at", t("primitive/uint"))
        .build()
}

fn system_registry_register_result() -> TypeDefinition {
    // `binding_hash` present on approval; `status` carries "pending_review"
    // (manual mode) when no binding was issued.
    TypeDefBuilder::new("system/registry/register-result")
        .field("binding_hash", opt("system/hash"))
        .field("status", opt("primitive/string"))
        .build()
}

fn system_registry_issuer_policy() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/issuer-policy")
        .field("mode", t("primitive/string"))
        .field("allowlist", opt_arr(t("system/peer-id")))
        .field("name_constraints", opt("primitive/string"))
        .field("default_ttl", opt("primitive/uint"))
        .build()
}

fn system_registry_revoke_request() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/revoke-request")
        .field("binding_hash", t("system/hash"))
        .field("reason", opt("primitive/string"))
        .build()
}

fn system_registry_renew_request() -> TypeDefinition {
    TypeDefBuilder::new("system/registry/renew-request")
        .field("binding_hash", t("system/hash"))
        .field("ttl", opt("primitive/uint"))
        .build()
}

// ============================================================================
// EXTENSION-DISCOVERY v1.0 — find-and-prompt substrate types (F1).
// candidate.peer_id is optional system/peer-id; identity-claim.peer_id is
// required. public_key_digest is raw bytes (V7 §1.5 digest, not a system/hash).
// ============================================================================

fn system_discovery_announce_request() -> TypeDefinition {
    TypeDefBuilder::new("system/discovery/announce-request")
        .field("backend", t("primitive/string"))
        .field("profile_ref", t("primitive/string"))
        .build()
}

fn system_discovery_announce_stop_request() -> TypeDefinition {
    TypeDefBuilder::new("system/discovery/announce-stop-request")
        .field("backend", t("primitive/string"))
        .field("profile_ref", t("primitive/string"))
        .build()
}

fn system_discovery_candidate() -> TypeDefinition {
    TypeDefBuilder::new("system/discovery/candidate")
        .field("peer_id", opt("system/peer-id"))
        .field("backend", t("primitive/string"))
        .field("observed_at", t("primitive/uint"))
        .field("endpoint_hint", opt("primitive/any"))
        .field("identity_hint", opt("system/hash"))
        .field("supersedes", opt("system/hash"))
        .build()
}

fn system_discovery_decision() -> TypeDefinition {
    TypeDefBuilder::new("system/discovery/decision")
        .field("candidate", t("system/hash"))
        .field("outcome", t("primitive/string"))
        .field("grant", opt("system/hash"))
        .field("decided_at", t("primitive/uint"))
        .build()
}

fn system_discovery_identity_claim() -> TypeDefinition {
    TypeDefBuilder::new("system/discovery/identity-claim")
        .field("peer_id", t("system/peer-id"))
        .field("key_type", t("primitive/uint"))
        .field("hash_type", t("primitive/uint"))
        .field("public_key_digest", t("primitive/bytes"))
        .build()
}

fn system_discovery_scan_request() -> TypeDefinition {
    TypeDefBuilder::new("system/discovery/scan-request")
        .field("backend", t("primitive/string"))
        .field("filter", opt_map(t("primitive/any")))
        .build()
}

fn system_discovery_scan_result() -> TypeDefinition {
    TypeDefBuilder::new("system/discovery/scan-result")
        .field("candidates", arr(t("system/hash")))
        .field("truncated", t("primitive/bool"))
        .field("code", opt("primitive/string"))
        .build()
}

// ============================================================================
// EXTENSION-RELAY v1.0 — opaque-envelope transport types (F1). Register
// advertise-limits before advertise (nested type-ref). envelope_inner is the
// content-hash pointer to the inner envelope (system/hash). forward-request.
// route stays array_of(primitive/string) to match the Go oracle (see
// docs/SPEC-AMBIGUITIES.md — Go does not pin route hops to system/peer-id).
// ============================================================================

fn system_relay_advertise_limits() -> TypeDefinition {
    TypeDefBuilder::new("system/relay/advertise-limits")
        .field("max_envelope_size", opt("primitive/uint"))
        .field("max_storage_bytes", opt("primitive/uint"))
        .field("forward_rate_limit", opt("primitive/uint"))
        .build()
}

fn system_relay_advertise() -> TypeDefinition {
    TypeDefBuilder::new("system/relay/advertise")
        .field("modes", arr(t("primitive/string")))
        .field("endpoints", arr(t("primitive/any")))
        .field("limits", t("system/relay/advertise-limits"))
        .field("caps_required", arr(t("primitive/string")))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

fn system_relay_forward_request() -> TypeDefinition {
    TypeDefBuilder::new("system/relay/forward-request")
        .field("destination", t("system/peer-id"))
        .field("route", opt_arr(t("primitive/string")))
        .field("next_hop", opt("system/peer-id"))
        .field("ttl_hops", t("primitive/uint"))
        .field("envelope_inner", t("system/hash"))
        .build()
}

fn system_relay_forward_result() -> TypeDefinition {
    TypeDefBuilder::new("system/relay/forward-result")
        .field("status", t("primitive/string"))
        .field("next_hop", opt("system/peer-id"))
        .field("stored_at", opt("primitive/string"))
        .build()
}

fn system_relay_poll_request() -> TypeDefinition {
    TypeDefBuilder::new("system/relay/poll-request")
        .field("namespace", t("primitive/string"))
        .field("since", opt("primitive/any"))
        .field("limit", opt("primitive/uint"))
        .build()
}

fn system_relay_poll_result() -> TypeDefinition {
    TypeDefBuilder::new("system/relay/poll-result")
        .field("entries", arr(t("system/hash")))
        .field("cursor", t("primitive/any"))
        .field("has_more", t("primitive/bool"))
        .build()
}

fn system_relay_put_result() -> TypeDefinition {
    TypeDefBuilder::new("system/relay/put-result")
        .field("status", t("primitive/string"))
        .field("stored_at", t("primitive/string"))
        .field("entry_hash", t("system/hash"))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

fn system_relay_store_entry() -> TypeDefinition {
    TypeDefBuilder::new("system/relay/store-entry")
        .field("namespace", t("primitive/string"))
        .field("expires_at", opt("primitive/uint"))
        .field("put_by", t("system/peer-id"))
        .field("envelope_inner", t("system/hash"))
        .build()
}

// ============================================================================
// EXTENSION-ROUTE v1.0 — routing-table entry (F1). `match` stays
// primitive/string (the "*" default-route token is not a peer-id); `via` is
// the optional next-hop peer-id.
// ============================================================================

fn system_route() -> TypeDefinition {
    TypeDefBuilder::new("system/route")
        .field("match", t("primitive/string"))
        .field("action", t("primitive/string"))
        .field("via", opt("system/peer-id"))
        .field("metric", opt("primitive/uint"))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

// ============================================================================
// PEER inbox-relay (EXTENSION-RELAY v1.0 §3.5 MX-equivalent declaration, F1).
// Register inbox-relay-entry before inbox-relay (nested type-ref). relay is
// the holding relay's peer-id.
// ============================================================================

fn system_peer_inbox_relay_entry() -> TypeDefinition {
    TypeDefBuilder::new("system/peer/inbox-relay-entry")
        .field("relay", t("system/peer-id"))
        .field("namespace", t("primitive/string"))
        .field("priority", t("primitive/uint"))
        .build()
}

fn system_peer_inbox_relay() -> TypeDefinition {
    TypeDefBuilder::new("system/peer/inbox-relay")
        .field("relays", arr(t("system/peer/inbox-relay-entry")))
        .field("expires_at", opt("primitive/uint"))
        .build()
}

// ============================================================================
// Encryption (EXTENSION-ENCRYPTION v1.0). No handler op is dispatched over the
// wire — encryption is a client-side primitive (§13) — but the entity types
// MUST be registered so tree:put of a system/encrypted / system/encryption-
// pubkey / handoff / revocation / key-backup entity is accepted by every
// conformant peer. The two sub-shape types (kdf-params, wrapped-key) are the
// R4-blessed names for the §6.1 kdf_params block and the §8.2 wrapped_keys
// element (arch v2.5 ruling R4; Go reference core/types/
// encryption.go). Field shapes mirror Go's reflected EncryptedData etc.;
// omitempty fields map to optional. Sub-shapes register before the outer
// wrapper so the nested type-ref resolves.
// ============================================================================

/// §6.1 / §9.2 Argon2id parameter sub-shape (all five params required uints).
fn system_encryption_kdf_params() -> TypeDefinition {
    TypeDefBuilder::new("system/encryption/kdf-params")
        .field("argon2_version", t("primitive/uint"))
        .field("memory_cost", t("primitive/uint"))
        .field("time_cost", t("primitive/uint"))
        .field("parallelism", t("primitive/uint"))
        .field("output_len", t("primitive/uint"))
        .build()
}

/// §8.2 per-member group wrap entry. `recipient_key` is the inner pubkey-entity
/// content_hash (uniform at every tier, F-GO-1).
fn system_encryption_wrapped_key() -> TypeDefinition {
    TypeDefBuilder::new("system/encryption/wrapped-key")
        .field("recipient_key", t("system/hash"))
        .field("enc_key_type", t("primitive/uint"))
        .field("ephemeral_key", t("primitive/bytes"))
        .field("wrapped_aead_key", t("primitive/bytes"))
        .field("wrap_nonce", t("primitive/bytes"))
        .build()
}

/// §4.1 content-addressed inner pubkey entity.
fn system_encryption_pubkey() -> TypeDefinition {
    TypeDefBuilder::new("system/encryption-pubkey")
        .field("enc_key_type", t("primitive/uint"))
        .field("public_key", t("primitive/bytes"))
        .field("supported_aead_ids", arr(t("primitive/uint")))
        .field("supported_kdf_ids", arr(t("primitive/uint")))
        .field("created", t("primitive/uint"))
        .field("expires", opt("primitive/uint"))
        .build()
}

/// §5.1 outer wrapper, unioned across modes. Per-mode additional fields
/// (§6.1 self, §7.2 peer, §8.2 group) are optional; `mode` discriminates.
fn system_encrypted() -> TypeDefinition {
    TypeDefBuilder::new("system/encrypted")
        .field("mode", t("primitive/string"))
        .field("enc_key_type", t("primitive/uint"))
        .field("aead_id", t("primitive/uint"))
        .field("kdf_id", t("primitive/uint"))
        .field("nonce", t("primitive/bytes"))
        .field("ciphertext", t("primitive/bytes"))
        // Self-mode additions (§6.1).
        .field("key_id", opt("primitive/string"))
        .field("kdf_salt", opt("primitive/bytes"))
        .field("kdf_params", opt("system/encryption/kdf-params"))
        // Peer-mode additions (§7.2).
        .field("ephemeral_key", opt("primitive/bytes"))
        .field("recipient_key", opt("system/hash"))
        // Group-mode additions (§8.2).
        .field("wrapped_keys", opt_arr(t("system/encryption/wrapped-key")))
        .build()
}

/// §10.1 Tier-A rotation handoff (dual-signed via system/signature pointer).
fn system_encryption_handoff() -> TypeDefinition {
    TypeDefBuilder::new("system/encryption/handoff")
        .field("previous_pubkey", t("system/hash"))
        .field("next_pubkey", t("system/hash"))
        .field("created", t("primitive/uint"))
        .build()
}

/// §11.1 Tier-A revocation (signed by the peer's V7 keypair).
fn system_encryption_revocation() -> TypeDefinition {
    TypeDefBuilder::new("system/encryption/revocation")
        .field("revokes", t("system/hash"))
        .field("reason", opt("primitive/string"))
        .field("created", t("primitive/uint"))
        .build()
}

/// §9.2 Tier-2 passphrase-wrapped key backup. `kdf_params` here is a required
/// value (non-pointer in Go), unlike the optional self-mode wrapper field.
fn system_encryption_key_backup() -> TypeDefinition {
    TypeDefBuilder::new("system/encryption/key-backup")
        .field("pubkey_ref", t("system/hash"))
        .field("kdf_salt", t("primitive/bytes"))
        .field("kdf_params", t("system/encryption/kdf-params"))
        .field("wrap_nonce", t("primitive/bytes"))
        .field("wrapped_key", t("primitive/bytes"))
        .build()
}

/// §16 ENC-KAT-INNER carrier type (arch ruling R3). The KAT
/// plaintext is the ECF of a `system/note` entity, not a bare string —
/// exercising the decrypt → typed-entity → re-inject path (§13.3).
fn system_note() -> TypeDefinition {
    TypeDefBuilder::new("system/note")
        .field("body", t("primitive/string"))
        .field("created", t("primitive/uint"))
        .build()
}

// ============================================================================
// EXTENSION-TYPE §7.4-7.6 — type adopt / converge / reconcile request+result.
// type_paths/source_path retyped to system/tree/path; reconciled_type is the
// full merged type entity (core/entity).
// ============================================================================

fn system_type_adopt_request() -> TypeDefinition {
    TypeDefBuilder::new("system/type/adopt-request")
        .field("source_path", t("system/tree/path"))
        .field("local_name", opt("system/type/name"))
        .build()
}

fn system_type_converge_request() -> TypeDefinition {
    TypeDefBuilder::new("system/type/converge-request")
        .field("type_paths", arr(t("system/tree/path")))
        .build()
}

fn system_type_reconcile_request() -> TypeDefinition {
    TypeDefBuilder::new("system/type/reconcile-request")
        .field("type_paths", arr(t("system/tree/path")))
        .field("strategy", t("primitive/string"))
        .build()
}

fn system_type_reconcile_result() -> TypeDefinition {
    TypeDefBuilder::new("system/type/reconcile-result")
        .field("reconciled_type", t("core/entity"))
        .field("strategy_used", t("primitive/string"))
        .field("sources", arr(t("system/tree/path")))
        .field("fields_dropped", opt_arr(t("primitive/string")))
        .field("fields_made_optional", opt_arr(t("primitive/string")))
        .field(
            "incompatibilities",
            opt_arr(t("system/type/field-incompatibility")),
        )
        .build()
}

/// Register all core type definitions into the given registry.
pub fn register_core_types(registry: &TypeRegistry) {
    for td in all_core_types() {
        registry.register(td);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_types_count() {
        let types = all_core_types();
        assert!(
            types.len() >= 94,
            "Expected at least 94 types, got {}",
            types.len()
        );
    }

    #[test]
    fn test_all_types_unique_names() {
        let types = all_core_types();
        let mut names: Vec<&str> = types.iter().map(|t| t.name.as_str()).collect();
        let total = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total, "Duplicate type names found");
    }

    #[test]
    fn test_all_types_to_entity() {
        for td in all_core_types() {
            let entity = td.to_entity().unwrap_or_else(|e| {
                panic!("Failed to create entity for type {}: {}", td.name, e)
            });
            assert_eq!(entity.entity_type, "system/type");
            assert!(
                entity.validate().is_ok(),
                "Entity validation failed for type {}",
                td.name
            );
        }
    }

    #[test]
    fn test_register_core_types() {
        let registry = TypeRegistry::new();
        register_core_types(&registry);
        assert!(registry.has("primitive/string"));
        assert!(registry.has("system/hash"));
        assert!(registry.has("system/type"));
        assert!(registry.has("system/protocol/connect/hello"));
        assert!(registry.has("system/handler"));
        assert!(registry.has("system/handler/manifest"));
        assert!(registry.has("system/capability/token"));
        assert!(registry.has("system/continuation"));
    }

    /// Cross-impl validator (`validate-peer -category type_system`) verifies
    /// the multi-sig primitive types per PROPOSAL-MULTISIG-CORE-PRIMITIVE
    /// §M1 + §M2: `system/capability/multi-granter` registered;
    /// `system/capability/token.granter` is union_of(system/hash,
    /// system/capability/multi-granter).
    #[test]
    fn test_multisig_primitive_types_registered() {
        let registry = TypeRegistry::new();
        register_core_types(&registry);
        // M2: multi-granter type registered.
        assert!(
            registry.has("system/capability/multi-granter"),
            "PROPOSAL-MULTISIG-CORE-PRIMITIVE §M2 type not registered"
        );
        // M1: token.granter is a union, not a plain system/hash.
        let token = registry
            .get("system/capability/token")
            .expect("system/capability/token must be registered");
        let granter = token
            .fields
            .get("granter")
            .expect("granter field must exist");
        assert!(
            !granter.union_of.is_empty(),
            "token.granter MUST be union_of per §M1, was: {:?}",
            granter
        );
        // Union must include both variants.
        let variant_refs: Vec<&str> = granter
            .union_of
            .iter()
            .filter_map(|v| v.type_ref.as_deref())
            .collect();
        assert!(
            variant_refs.contains(&"system/hash"),
            "granter union missing system/hash variant: {:?}",
            variant_refs
        );
        assert!(
            variant_refs.contains(&"system/capability/multi-granter"),
            "granter union missing system/capability/multi-granter variant: {:?}",
            variant_refs
        );
    }

    /// Cross-impl validator (`validate-peer -category {attestation,quorum,identity}`)
    /// verifies the substrate primitives + handler op request/result types
    /// per EXTENSION-ATTESTATION v1.1, EXTENSION-QUORUM v1.1, EXTENSION-IDENTITY v3.3.
    /// Naming convention per V7 precedent (logged at SPEC-AMBIGUITIES SPEC-24).
    #[test]
    fn test_identity_v33_types_registered() {
        let registry = TypeRegistry::new();
        register_core_types(&registry);
        for name in [
            // Substrate entity types
            "system/attestation",
            "system/quorum",
            // Attestation handler op types (8)
            "system/attestation/create-request",
            "system/attestation/create-result",
            "system/attestation/supersede-request",
            "system/attestation/supersede-result",
            "system/attestation/revoke-request",
            "system/attestation/revoke-result",
            "system/attestation/verify-request",
            "system/attestation/verify-result",
            // Quorum handler op types (8)
            "system/quorum/create-request",
            "system/quorum/create-result",
            "system/quorum/update-request",
            "system/quorum/update-result",
            "system/quorum/publish-request",
            "system/quorum/publish-result",
            "system/quorum/verify-request",
            "system/quorum/verify-result",
            // Identity-owned entity types
            "system/identity/peer-config",
            "system/identity/identity-binding",
            // Identity handler op types (12)
            "system/identity/configure-request",
            "system/identity/configure-result",
            "system/identity/create-quorum-request",
            "system/identity/create-quorum-result",
            "system/identity/create-attestation-request",
            "system/identity/create-attestation-result",
            "system/identity/supersede-attestation-request",
            "system/identity/supersede-attestation-result",
            "system/identity/revoke-attestation-request",
            "system/identity/revoke-attestation-result",
            "system/identity/publish-attestation-request",
            "system/identity/publish-attestation-result",
        ] {
            assert!(
                registry.has(name),
                "v3.3 type {} not registered",
                name
            );
        }
        // v2.2 names that MUST NOT be present after v3.2 migration.
        for absent in ["system/identity/quorum", "system/identity/attestation"] {
            assert!(
                !registry.has(absent),
                "v2.2 type {} should not be registered in v3.3",
                absent
            );
        }
    }

    #[test]
    fn test_system_hash_has_byte_size() {
        let h = system_hash();
        let fc = h.fields.get("format_code").unwrap();
        assert_eq!(fc.byte_size, Some(1));
    }

    #[test]
    fn test_handler_no_longer_extends_interface() {
        let h = system_handler();
        assert_eq!(h.extends, None);
    }

    #[test]
    fn test_handler_manifest_extends_interface() {
        let m = system_handler_manifest();
        assert_eq!(m.extends, Some("system/handler/interface".to_string()));
    }

    #[test]
    fn test_different_types_different_hashes() {
        let handler = system_handler();
        let hello = system_protocol_connect_hello();
        let h_entity = handler.to_entity().unwrap();
        let hello_entity = hello.to_entity().unwrap();
        assert_ne!(h_entity.content_hash, hello_entity.content_hash);
    }
}
