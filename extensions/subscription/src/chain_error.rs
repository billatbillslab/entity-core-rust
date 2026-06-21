//! Subscription-side chain-error marker emission per EXTENSION-SUBSCRIPTION §4.7.
//!
//! Mirrors the EXTENSION-CONTINUATION §3.10 `write_lost_error_marker` pattern.
//! Helpers (sanitize_reason_segment, peer_id_from_uri, classify_transport_failure)
//! are duplicated rather than imported because cross-extension deps beyond the
//! substrate-style three (quorum→attestation, role→attestation,
//! identity→attestation+quorum) are forbidden per CLAUDE.md. If the pattern
//! recurs in extensions/inbox or extensions/revision implementations, lift to
//! a shared core crate.

use std::sync::Arc;

use entity_entity::Entity;
use entity_store::{ContentStore, LocationIndex};

/// Reason codes for limit-suppression cases (§4.6).
pub(crate) const REASON_MAX_EVENTS_REACHED: &str = "max_events_reached";
pub(crate) const REASON_MAX_DURATION_REACHED: &str = "max_duration_reached";
pub(crate) const REASON_RATE_LIMITED: &str = "rate_limited";

/// Reason codes for capability-state failures at delivery-eligibility check.
pub(crate) const REASON_CAPABILITY_DENIED: &str = "capability_denied";

/// V7 §6.12 transport codes for terminal delivery failures.
const REASON_RECV_TIMEOUT: &str = "recv_timeout";
const REASON_CONNECTION_BROKEN: &str = "connection_broken";
const REASON_PROTOCOL_ERROR: &str = "protocol_error";

/// Path-safety sanitizer per EXTENSION-CONTINUATION v1.19 §3.10.5
/// (V7 §1.4 path-segment rules). See note in module header re: duplication.
pub(crate) fn sanitize_reason_segment(reason: &str) -> String {
    if reason.is_empty() {
        return "unspecified_error".to_string();
    }
    for b in reason.bytes() {
        if b == 0 || b == b'/' || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            return "unspecified_error".to_string();
        }
        if b < 0x20 || b == 0x7f {
            return "unspecified_error".to_string();
        }
    }
    reason.to_string()
}

/// Best-effort extract the target peer ID from an absolute URI of the form
/// `entity://{peer_id}/...` or `/{peer_id}/...`.
pub(crate) fn peer_id_from_uri(uri: &str) -> Option<String> {
    if let Some(rest) = uri.strip_prefix("entity://") {
        if let Some(slash) = rest.find('/') {
            return Some(rest[..slash].to_string());
        }
        return Some(rest.to_string());
    }
    if let Some(rest) = uri.strip_prefix('/') {
        if let Some(slash) = rest.find('/') {
            return Some(rest[..slash].to_string());
        }
        return Some(rest.to_string());
    }
    None
}

/// Classify a delivery-side `HandlerError::Internal`-shaped failure into a
/// V7 §6.12 transport code. Mirrors `extensions/continuation::classify_transport_failure`
/// — pattern strings track the same message shapes used by `send_execute`.
pub(crate) fn classify_transport_failure(err_text: &str) -> &'static str {
    let lower = err_text.to_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        REASON_RECV_TIMEOUT
    } else if lower.contains("reader task terminated")
        || lower.contains("connection")
        || lower.contains("broken pipe")
        || lower.contains("eof")
    {
        REASON_CONNECTION_BROKEN
    } else {
        // Decode/parse/malformed plus unknown shapes both surface as
        // protocol_error per V7 §6.12 ("consumer has no other code to record"
        // fallback), matching the continuation classifier's posture.
        REASON_PROTOCOL_ERROR
    }
}

/// Capture failure-origination timestamp in Unix milliseconds.
/// Same discipline as EXTENSION-CONTINUATION v1.20 §3.10.6 — caller stamps
/// at failure-origination, not at marker-bind time, so retries of the same
/// logical event dedupe to the same content hash.
pub(crate) fn capture_failure_timestamp_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Bind a `lost`-variant chain-error marker for a subscription delivery
/// failure per EXTENSION-SUBSCRIPTION §4.7.
///
/// Path scheme:
/// `/{local_peer_id}/system/runtime/chain-errors/lost/{chain_id}/{subscription_id}/{reason}/{marker_hash}`
///
/// `{step_index}` is `{subscription_id}` per §4.7 — the trigger is a tree
/// change rather than a chained EXECUTE, so no original-request-id is
/// available. `{chain_id}` is inherited from the source change's chain
/// causality per §4.5; when context propagation fails (empty `chain_id`),
/// we fall back to `subscription_id` so the marker still binds at a
/// well-formed path rather than `lost//{...}`.
///
/// Per §4.7: marker is informational — MUST NOT trigger advancement,
/// retry, or any reactive behavior beyond surfacing the failure for
/// inspect tooling and `validate-peer`'s `CAT-CHAIN-COMPLETION` check.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_lost_error_marker(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    local_peer_id: &str,
    chain_id: &str,
    subscription_id: &str,
    deliver_uri: &str,
    reason: &str,
    status: u32,
    timestamp_ms: u64,
) {
    let safe_reason = sanitize_reason_segment(reason);
    let chain_id_segment = if chain_id.is_empty() {
        subscription_id
    } else {
        chain_id
    };
    let target_peer_id = peer_id_from_uri(deliver_uri).unwrap_or_default();

    let body_fields = vec![
        (
            entity_ecf::text("chain_id"),
            entity_ecf::text(chain_id_segment),
        ),
        (entity_ecf::text("code"), entity_ecf::text(reason)),
        (entity_ecf::text("reason"), entity_ecf::text(&safe_reason)),
        (
            entity_ecf::text("status"),
            entity_ecf::integer(status as i64),
        ),
        (
            entity_ecf::text("step_index"),
            entity_ecf::text(subscription_id),
        ),
        (
            entity_ecf::text("target_peer_id"),
            entity_ecf::text(&target_peer_id),
        ),
        (entity_ecf::text("target_uri"), entity_ecf::text(deliver_uri)),
        (
            entity_ecf::text("timestamp"),
            entity_ecf::integer(timestamp_ms as i64),
        ),
    ];
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(body_fields));
    let entity = match Entity::new("system/runtime/chain-error-lost", data) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                subscription_id = %subscription_id,
                reason = %safe_reason,
                error = %e,
                "subscription §4.7: lost-error marker entity build FAILED"
            );
            return;
        }
    };
    let marker_path = format!(
        "/{}/system/runtime/chain-errors/lost/{}/{}/{}/{}",
        local_peer_id,
        chain_id_segment,
        subscription_id,
        safe_reason,
        entity.content_hash.to_hex(),
    );
    match content_store.put(entity) {
        Ok(h) => {
            location_index.set(&marker_path, h);
        }
        Err(e) => {
            tracing::warn!(
                path = %marker_path,
                error = %e,
                "subscription §4.7: lost-error marker bind FAILED"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_returns_unspecified_for_slashes() {
        assert_eq!(sanitize_reason_segment("has/slash"), "unspecified_error");
        assert_eq!(sanitize_reason_segment("has space"), "unspecified_error");
        assert_eq!(sanitize_reason_segment(""), "unspecified_error");
    }

    #[test]
    fn sanitize_passes_path_safe_strings() {
        assert_eq!(sanitize_reason_segment("rate_limited"), "rate_limited");
        assert_eq!(
            sanitize_reason_segment("max_events_reached"),
            "max_events_reached"
        );
        assert_eq!(sanitize_reason_segment("recv_timeout"), "recv_timeout");
    }

    #[test]
    fn peer_id_from_uri_handles_both_schemes() {
        assert_eq!(
            peer_id_from_uri("entity://peer123/path/to/thing"),
            Some("peer123".to_string())
        );
        assert_eq!(
            peer_id_from_uri("/peer123/path/to/thing"),
            Some("peer123".to_string())
        );
        assert_eq!(peer_id_from_uri("relative/path"), None);
    }

    #[test]
    fn classify_transport_failure_maps_known_strings() {
        assert_eq!(classify_transport_failure("request timed out"), "recv_timeout");
        assert_eq!(
            classify_transport_failure("connection reset by peer"),
            "connection_broken"
        );
        assert_eq!(
            classify_transport_failure("decode error: malformed CBOR"),
            "protocol_error"
        );
        assert_eq!(classify_transport_failure("totally unknown"), "protocol_error");
    }
}
