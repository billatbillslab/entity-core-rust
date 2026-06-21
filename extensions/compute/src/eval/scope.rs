//! Closure scope serialization (v3.19b — kind-tagged bindings).
//!
//! `capture_scope` writes a `compute/scope` entity whose `bindings` map
//! contains kind-tagged values per `EXTENSION-COMPUTE.md` §2.3 / N1:
//!
//!   - `{kind: "entity", entity_hash: <system/hash>}` for any entity-valued
//!     binding (entity / closure / error). The bytes are the entity's
//!     `content_hash` on the wire (`algorithm || digest`); length is
//!     determined by the hash algorithm — variable per V7 §1.2.
//!   - `{kind: "value",  value: <bare CBOR>}` for primitive / record bindings.
//!
//! `load_scope` reads the kind tag and resolves entity hashes via the
//! content-store-direct path (N6), inheriting the closure's authorization (N4
//! — no `is_compute_type` / sealed-set gate). **Eager resolution (v3.19b
//! close-out):** all bindings are resolved on apply; a
//! `kind:"entity"` binding hash that resolves in neither the envelope
//! `included` map nor the content store fails the apply itself with
//! `ComputeError::ScopeUnreachable` (N8). Empirical 2/3 cross-impl + spec
//! text "at apply time" + F9-B intent all support eager — the closure's
//! identity covers all its bindings, and a latent unreachable binding hidden
//! by lazy resolution would surface only after a refactor that happens to
//! reference it.
//!
//! All three boundaries the v3.19b §2.3 block calls out (scope / construct /
//! apply) share the "reference, don't duplicate" rule; this module owns the
//! scope boundary. Construct and apply already encode entity-valued things as
//! `system/hash` content-hash refs (`compute_value_to_cbor` in `eval/mod.rs`),
//! consistent with N1.

use ciborium::Value;
use entity_ecf::ValueExt;

use entity_entity::Entity;
use entity_hash::Hash;

use crate::types::*;

use super::EvalContext;

// ---------------------------------------------------------------------------
// Capture (§4.4, v3.19b §2.3)
// ---------------------------------------------------------------------------

/// Capture scope as a `compute/scope` entity with v3.19b kind-tagged bindings.
///
/// **N1 — reference, don't duplicate.** Entity / closure / error bindings are
/// emitted as `{kind:"entity", entity_hash}` after ensuring the referenced
/// entity is resident in the content store. Primitive / Uint bindings are
/// emitted as `{kind:"value", value}` inline; the ephemeral uint cast tag is
/// stripped at the binding boundary (§2.2 rule 11).
///
/// The scope entity is written to the content store and `mark_encountered`'d
/// for same-evaluation resolvability (§1572). For cross-peer transfer (N7) the
/// scope subtree would arrive via the envelope `included` map; same-peer is
/// the path provided today.
pub(super) fn capture_scope(scope: &Scope, ctx: &mut EvalContext<'_>) -> Option<Hash> {
    if scope.bindings.is_empty() {
        return None;
    }

    // ECF canonical map ordering on binding names: encoded byte length, then
    // lexical. `BTreeMap` already iterates in byte-lex order; we re-sort by
    // encoded length so multi-byte UTF-8 names ride the canonical rule.
    let mut names: Vec<&String> = scope.bindings.keys().collect();
    names.sort_by(|a, b| {
        let al = ecf_key_encoded_len(a);
        let bl = ecf_key_encoded_len(b);
        al.cmp(&bl).then_with(|| a.as_bytes().cmp(b.as_bytes()))
    });

    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(names.len());
    for name in names {
        let binding = encode_scope_binding(&scope.bindings[name], ctx);
        entries.push((Value::Text(name.clone()), binding));
    }

    let data = entity_ecf::cbor_map! {
        "bindings" => Value::Map(entries)
    };
    let data_bytes = entity_ecf::to_ecf(&data);
    let entity = Entity::new(TYPE_SCOPE, data_bytes).expect("scope entity");
    let hash = entity.content_hash;
    ctx.encountered.insert(hash, entity.clone());
    let _ = ctx.content_store.put(entity);
    Some(hash)
}

/// Encode a single value as a kind-tagged map (v3.19b §2.3 N1 + v3.19c A.4).
///
/// Shared by scope-binding capture and `compute/construct` field encoding —
/// per the v3.19c A.4 "reuse the scope encoder" pin, the two boundaries
/// produce the same wire shape so cross-impl hash determinism holds at both.
pub(crate) fn encode_scope_binding(value: &ComputeValue, ctx: &mut EvalContext<'_>) -> Value {
    match value {
        ComputeValue::Entity(e) => {
            // N1 capture-side residency: the referenced entity MUST be in the
            // content store before its hash goes on the wire. `put` is
            // idempotent (content addressing) — cheap when already present.
            let _ = ctx.content_store.put(e.clone());
            kind_entity_binding(&e.content_hash)
        }
        ComputeValue::Closure(c) => {
            let e = c.to_entity();
            let h = e.content_hash;
            let _ = ctx.content_store.put(e);
            kind_entity_binding(&h)
        }
        ComputeValue::Error(err) => {
            let e = err.to_entity();
            let h = e.content_hash;
            let _ = ctx.content_store.put(e);
            kind_entity_binding(&h)
        }
        ComputeValue::Primitive(v) => kind_value_binding(v.clone()),
        ComputeValue::Uint(u) => {
            // §2.2 rule 11: strip the ephemeral cast tag at the binding boundary.
            kind_value_binding(Value::Integer(ciborium::value::Integer::from(*u as i64)))
        }
    }
}

/// `{kind: "entity", entity_hash: <bytes>}` — canonical ECF ordering: "kind"
/// (4 chars) sorts before "entity_hash" (11 chars).
fn kind_entity_binding(hash: &Hash) -> Value {
    Value::Map(vec![
        (Value::Text("kind".into()), Value::Text("entity".into())),
        (
            Value::Text("entity_hash".into()),
            Value::Bytes(hash.to_bytes().to_vec()),
        ),
    ])
}

/// `{kind: "value", value: <bare>}` — canonical ECF ordering: "kind" (4 chars)
/// sorts before "value" (5 chars).
fn kind_value_binding(value: Value) -> Value {
    Value::Map(vec![
        (Value::Text("kind".into()), Value::Text("value".into())),
        (Value::Text("value".into()), value),
    ])
}

// ---------------------------------------------------------------------------
// Load (§4.3, v3.19b §2.3 N4 + N6 + N8)
// ---------------------------------------------------------------------------

/// Load a scope from a `compute/scope` entity hash.
///
/// **Eager (v3.19b close-out).** All bindings are resolved at apply time; the
/// first `kind:"entity"` binding whose hash doesn't resolve aborts the load
/// with `Err(ComputeError::ScopeUnreachable(_))`. Callers propagate the error
/// as a value at status 200 (F10).
///
/// **N6 — content-store-direct.** Scope and binding entities resolve via the
/// envelope `included` map (§4.2 tier 1, when populated by N7's deferred wire)
/// and the local content store. The tree-scoped resolution tier and the
/// `validate_compute_resolvable` gate (`is_compute_type` / sealed-set) are
/// bypassed for scope resolution: the closure was already authorized at its
/// referencing context, and its bindings are structurally part of it (N4).
///
/// When the scope entity itself can't be resolved (legacy §1546 path), this
/// returns `Ok(Scope::new())` — the closure-apply site has already produced
/// the "closure scope entity not found" `not_found` error before getting here.
pub(crate) fn load_scope(
    env_hash: &Option<Hash>,
    ctx: &mut EvalContext<'_>,
) -> Result<Scope, ComputeError> {
    let hash = match env_hash {
        Some(h) => h,
        None => return Ok(Scope::new()),
    };

    let entity = match resolve_scope_entity(hash, ctx) {
        Some(e) => e,
        None => return Ok(Scope::new()),
    };

    ctx.encountered.insert(*hash, entity.clone());

    let data = match decode_data(&entity) {
        Some(d) => d,
        None => return Ok(Scope::new()),
    };

    let mut scope = Scope::new();
    if let Some(Value::Map(entries)) = data.get("bindings") {
        for (k, binding) in entries {
            if let Value::Text(name) = k {
                let value = decode_scope_binding(binding, ctx)?;
                scope.set(name.clone(), value);
            }
        }
    }

    Ok(scope)
}

/// Resolve a scope-related hash via envelope-included first, content store
/// second (v3.19b N6 + the §4.2 tier-1 envelope-included path for the deferred
/// N7 cross-peer arrival).
fn resolve_scope_entity(hash: &Hash, ctx: &EvalContext<'_>) -> Option<Entity> {
    if let Some(e) = ctx.included.get(hash) {
        return Some(e.clone());
    }
    ctx.content_store.get(hash)
}

/// Decode a single kind-tagged binding. **Eager:** an unresolvable entity
/// hash (or any malformed shape) returns `Err(ScopeUnreachable)`, aborting
/// the entire `load_scope` per the v3.19b close-out empirical pin.
fn decode_scope_binding(
    binding: &Value,
    ctx: &mut EvalContext<'_>,
) -> Result<ComputeValue, ComputeError> {
    let kind = binding
        .get("kind")
        .and_then(|v| v.as_text())
        .ok_or_else(|| {
            ComputeError::ScopeUnreachable("scope binding missing 'kind' discriminator".into())
        })?;

    match kind {
        "entity" => {
            let bytes = binding
                .get("entity_hash")
                .and_then(|v| match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    ComputeError::ScopeUnreachable(
                        "kind:\"entity\" binding missing 'entity_hash'".into(),
                    )
                })?;
            let hash = Hash::from_bytes(&bytes).map_err(|_| {
                ComputeError::ScopeUnreachable(
                    "kind:\"entity\" binding has malformed entity_hash".into(),
                )
            })?;
            // N4 + N6: content-store-direct (with envelope-included on the
            // happy path for cross-peer arrivals).
            let resolved = resolve_scope_entity(&hash, ctx).ok_or_else(|| {
                ComputeError::ScopeUnreachable(format!(
                    "scope binding entity not resolvable: {}",
                    hash
                ))
            })?;
            ctx.encountered.insert(hash, resolved.clone());
            // Closure entity → reconstruct the in-memory variant so existing
            // closure-apply consumers see Closure, not Entity.
            if resolved.entity_type == TYPE_CLOSURE {
                if let Some(closure) = parse_closure_entity(&resolved) {
                    return Ok(ComputeValue::Closure(closure));
                }
            }
            // `compute/error` stays as Entity; v3.19b `is_error` covers
            // TYPE_ERROR entities, so it propagates NaN-style.
            Ok(ComputeValue::Entity(resolved))
        }
        "value" => {
            let v = binding.get("value").ok_or_else(|| {
                ComputeError::ScopeUnreachable("kind:\"value\" binding missing 'value'".into())
            })?;
            Ok(ComputeValue::Primitive(v.clone()))
        }
        other => Err(ComputeError::ScopeUnreachable(format!(
            "scope binding has unknown kind: {}",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// Parse a `compute/closure` entity back into a `ClosureValue`.
pub(super) fn parse_closure_entity(entity: &Entity) -> Option<ClosureValue> {
    let data = decode_data(entity)?;
    let params = data_str_array(&data, "params")?;
    let body = data_hash(&data, "body")?;
    let env = data_hash(&data, "env");
    Some(ClosureValue { params, body, env })
}

// (Withdrawn with the v3.19c α revision.) The `try_unwrap_kind_tagged`
// + `decode_kind_entity` + `decode_kind_value` helpers — used by the prior
// kind-tagged-construct-output draft to unwrap construct fields at the read
// side — are removed: constructed entities are now materialized bare per V7
// §1.4 (`compute/construct` § A.3) so there are no kind-tags to unwrap on a
// non-scope surface. `compute/scope` bindings retain the kind-tag wire shape
// (§2.3 N1/N2); the decode path for those still lives in `decode_scope_binding`
// above, scoped to scope-binding deserialization only.

/// Byte length of a CBOR text string encoding for sorting purposes.
fn ecf_key_encoded_len(s: &str) -> usize {
    let text_bytes = entity_ecf::to_ecf(&Value::Text(s.to_string()));
    text_bytes.len()
}
