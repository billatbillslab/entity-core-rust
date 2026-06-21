//! Response builders for EXECUTE_RESPONSE entities.

use std::collections::HashMap;

use entity_entity::{Entity, Envelope};
use entity_hash::Hash;
use entity_types::{TYPE_ERROR, TYPE_EXECUTE_RESPONSE};

use crate::connect::decode_entity_from_value;
use crate::ProtocolError;

/// Build an EXECUTE_RESPONSE envelope (§3.3).
///
/// The `result` field contains the result entity inline (as a CBOR map),
/// and the entity is also included in the envelope's `included` map.
pub fn build_execute_response(
    request_id: &str,
    status: u32,
    result_entity: Entity,
) -> Result<Envelope, ProtocolError> {
    build_execute_response_with_included(request_id, status, result_entity, HashMap::new())
}

/// Build an EXECUTE_RESPONSE envelope with extra included entities.
///
/// Like `build_execute_response`, but also includes additional entities
/// in the envelope (e.g., version entities referenced by hash in a log result).
pub fn build_execute_response_with_included(
    request_id: &str,
    status: u32,
    result_entity: Entity,
    extra_included: HashMap<Hash, Entity>,
) -> Result<Envelope, ProtocolError> {
    build_execute_response_full(request_id, status, result_entity, extra_included, None)
}

/// Build an EXECUTE_RESPONSE envelope carrying the durability verdict field
/// (EXTENSION-DURABILITY §5). `durability_cbor`, when `Some`, is the CBOR-
/// encoded value of the durability field — a bare map of
/// `{requested, applied, committed?, max_available?, reason?}`, NOT a
/// `{type, data, content_hash}` entity wrapper. That wire convention
/// matches the other typed-struct fields (`deliver_to` / `bounds`) and is
/// what the cross-impl validator decodes. When `None`, the response is
/// shaped exactly as before (durability-unaware consumers are unaffected).
pub fn build_execute_response_full(
    request_id: &str,
    status: u32,
    result_entity: Entity,
    extra_included: HashMap<Hash, Entity>,
    durability_cbor: Option<Vec<u8>>,
) -> Result<Envelope, ProtocolError> {
    // Encode the result entity as an inline CBOR map for the result field.
    let result_encoded = entity_wire::encode_entity(&result_entity);

    // Build EXECUTE_RESPONSE data manually to embed raw entity bytes.
    // ECF key ordering (by encoded key byte length, then lexicographic of the
    // encoded key bytes):
    //   "result"     (6 chars) -> 7 encoded bytes
    //   "status"     (6 chars) -> 7 encoded bytes   ("result" < "status" lex)
    //   "durability" (10 chars) -> 11 encoded bytes
    //   "request_id" (10 chars) -> 11 encoded bytes ("durability" < "request_id")
    let mut data = Vec::new();
    if durability_cbor.is_some() {
        data.push(0xA4); // map(4)
    } else {
        data.push(0xA3); // map(3)
    }

    // "result" — inline entity map
    entity_ecf::encode_cbor_text(&mut data, "result");
    data.extend_from_slice(&result_encoded);

    // "status" — integer
    entity_ecf::encode_cbor_text(&mut data, "status");
    entity_ecf::encode_cbor_uint(&mut data, status as u64);

    // "durability" — bare CBOR map (NOT entity-wrapped), EXTENSION-DURABILITY §5
    if let Some(dur_bytes) = &durability_cbor {
        entity_ecf::encode_cbor_text(&mut data, "durability");
        data.extend_from_slice(dur_bytes);
    }

    // "request_id" — text
    entity_ecf::encode_cbor_text(&mut data, "request_id");
    entity_ecf::encode_cbor_text(&mut data, request_id);

    let response_entity = Entity::new(TYPE_EXECUTE_RESPONSE, data)
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;

    let mut envelope = Envelope::new(response_entity);
    envelope.include(result_entity);
    for (_, entity) in extra_included {
        envelope.include(entity);
    }

    Ok(envelope)
}

/// Build an error response envelope.
pub fn build_error_response(
    request_id: &str,
    status: u32,
    code: &str,
    message: &str,
) -> Result<Envelope, ProtocolError> {
    build_error_response_with_marker(request_id, status, code, message, None)
}

/// Build an error response envelope, optionally including the receiver-side
/// chain-error marker hash (EXTENSION-CONTINUATION v1.20 §3.10.4 mirror
/// pointer). The hash is included in `ErrorData.rejected_marker` so the
/// sender can bind a `lost`-variant mirror referencing the receiver's
/// `rejected`-variant marker. Additive optional field — callers/parsers
/// without it produce/consume valid envelopes.
pub fn build_error_response_with_marker(
    request_id: &str,
    status: u32,
    code: &str,
    message: &str,
    rejected_marker: Option<entity_hash::Hash>,
) -> Result<Envelope, ProtocolError> {
    // ECF key ordering: keys are sorted by encoded-key byte length, then
    // lexicographic. `code` (5) and `message` (8) come first; `rejected_marker`
    // (17) is last. `entity_ecf::to_ecf` handles the sort, so we can list
    // fields in any order here.
    let mut fields = vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ];
    if let Some(h) = rejected_marker {
        fields.push((
            entity_ecf::text("rejected_marker"),
            entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    let error_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));

    let error_entity = Entity::new(TYPE_ERROR, error_data)
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;

    build_execute_response(request_id, status, error_entity)
}

/// Extract `ErrorData.rejected_marker` from a parsed error result entity
/// (EXTENSION-CONTINUATION v1.20 §3.10.4 mirror pointer). Returns `None`
/// when the entity is not a `system/protocol/error` or the field is absent.
/// Senders inspect this on 403 responses to bind a mirroring `lost`-variant
/// chain-error marker per §3.10.2 cap-rejection mirror.
pub fn extract_rejected_marker(error_entity: &Entity) -> Option<entity_hash::Hash> {
    if error_entity.entity_type != TYPE_ERROR {
        return None;
    }
    let v: ciborium::Value = ciborium::from_reader(error_entity.data.as_slice()).ok()?;
    let map = v.as_map()?;
    for (k, val) in map {
        if k.as_text() == Some("rejected_marker") {
            if let ciborium::Value::Bytes(bytes) = val {
                return entity_hash::Hash::from_bytes(bytes).ok();
            }
        }
    }
    None
}

/// Parse an EXECUTE_RESPONSE envelope, extracting request_id, status, and result entity.
pub fn parse_execute_response(envelope: &Envelope) -> Result<ParsedResponse, ProtocolError> {
    if envelope.root.entity_type != TYPE_EXECUTE_RESPONSE {
        return Err(ProtocolError::Invalid(format!(
            "expected {}, got {}",
            TYPE_EXECUTE_RESPONSE, envelope.root.entity_type
        )));
    }

    let value: ciborium::Value = ciborium::from_reader(envelope.root.data.as_slice())
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| ProtocolError::Invalid("response data must be a map".into()))?;

    let mut request_id = None;
    let mut status = None;
    let mut result_entity = None;
    let mut durability = None;

    for (k, v) in map {
        match k.as_text() {
            Some("request_id") => request_id = v.as_text().map(|s| s.to_string()),
            Some("status") => status = v.as_integer().and_then(|i| u32::try_from(i).ok()),
            Some("result") => {
                result_entity = Some(decode_entity_from_value(v)?);
            }
            // EXTENSION-DURABILITY §5 — optional durability verdict. Bare
            // CBOR map of {requested, applied, committed?, max_available?,
            // reason?} (NOT an entity wrapper, same convention as
            // `deliver_to`/`bounds`).
            Some("durability") => {
                durability = Some(v.clone());
            }
            _ => {}
        }
    }

    // PROPOSAL-CROSS-IMPL-STANDARDIZATION-CATCHUP §2 dispatch-surface
    // result-equivalence: a handler returning a `system/envelope` (or any
    // shape that bundles supporting entities) places them in
    // envelope.included. The remote-dispatch surface MUST preserve that
    // subtree so the consumer reading the result back sees what the
    // external caller would have seen.
    let included: std::collections::HashMap<entity_hash::Hash, Entity> = envelope
        .included
        .iter()
        .map(|(h, e)| (*h, e.clone()))
        .collect();

    Ok(ParsedResponse {
        request_id: request_id.ok_or(ProtocolError::MissingField("request_id"))?,
        status: status.ok_or(ProtocolError::MissingField("status"))?,
        result: result_entity.ok_or(ProtocolError::MissingField("result"))?,
        durability,
        included,
    })
}

/// A parsed EXECUTE_RESPONSE.
pub struct ParsedResponse {
    pub request_id: String,
    pub status: u32,
    pub result: Entity,
    /// The durability verdict (EXTENSION-DURABILITY §5), present only when the
    /// request carried a durability marker. The value is the bare CBOR map
    /// `{requested, applied, committed?, max_available?, reason?}` — the
    /// same wire convention used for `deliver_to` and `bounds`.
    pub durability: Option<ciborium::Value>,
    /// Envelope `included` entities. PROPOSAL-CROSS-IMPL-STANDARDIZATION-
    /// CATCHUP §2: preserved on remote dispatch so the consumer reading the
    /// result back sees what an external caller would have seen.
    pub included: std::collections::HashMap<entity_hash::Hash, Entity>,
}

