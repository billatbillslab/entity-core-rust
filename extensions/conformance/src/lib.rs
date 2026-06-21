//! GUIDE-CONFORMANCE §7a — the two `system/validate/*` wire-gate handlers
//! behind a runtime opt-in.
//!
//! These handlers are conformance **scaffolding**: not core protocol, not an
//! extension primitive. They expose two existing core capabilities at
//! well-known patterns so a black-box validator can probe them:
//!
//!   - `system/validate/echo:echo` — exercises §6.13(a) resolve→dispatch
//!     (verbatim-echo contract).
//!   - `system/validate/dispatch-outbound:dispatch` — exercises §6.13(b)
//!     outbound seam routed through §6.11 reentry: the handler originates ONE
//!     outbound EXECUTE back to the caller over the same accepted connection.
//!
//! In a core-only peer (no compute / continuation / subscription / inbox)
//! neither capability has another wire-reachable trigger, which is the whole
//! reason this exists.
//!
//! Both are OFF by default. The wire-host opts in (typically a `--validate`
//! flag → `PeerBuilder::with_conformance_handlers()`); a peer without the
//! opt-in 404s both patterns and the validator SKIPs honestly per §7a.4.
//!
//! **Cap-passing convention (§7a.2a, ruled by the Go reference):** the three
//! reentry-authority entities ride **in-band, nested in params**
//! (`reentry_capability` / `reentry_granter` / `reentry_cap_signature`) — NOT
//! via the envelope `included` set. They are extracted with byte fidelity
//! (`entity_wire::cbor_map_field_raw`) and forwarded on the outbound EXECUTE
//! via the new `ExecuteOptions.included` channel (the Rust analog of Go's
//! `WithIncludedChain`).

use async_trait::async_trait;
use entity_entity::Entity;
use entity_handler::{
    error_entity, ExecuteOptions, Handler, HandlerContext, HandlerError, HandlerResult,
    STATUS_BAD_GATEWAY, STATUS_BAD_REQUEST, STATUS_INTERNAL_ERROR, STATUS_NOT_SUPPORTED,
};

/// `system/validate/echo` bare pattern.
pub const PATTERN_ECHO: &str = "system/validate/echo";
/// `system/validate/dispatch-outbound` bare pattern.
pub const PATTERN_DISPATCH_OUTBOUND: &str = "system/validate/dispatch-outbound";

fn qualify(local_peer_id: &str, bare: &str) -> String {
    format!("/{}/{}", local_peer_id, bare)
}

// ---------------------------------------------------------------------------
// EchoHandler — §7a.1 verbatim echo (proves §6.13(a)).
// ---------------------------------------------------------------------------

/// `system/validate/echo` — operation `echo` returns the params entity
/// verbatim. The §7a.1 contract is byte equality: `result.value` ==
/// `params.value` for any ECF value the caller passes, satisfied by returning
/// the params entity itself with no decode/re-encode roundtrip.
pub struct EchoHandler {
    qualified_pattern: String,
}

impl EchoHandler {
    pub fn new(local_peer_id: &str) -> Self {
        Self {
            qualified_pattern: qualify(local_peer_id, PATTERN_ECHO),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for EchoHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        if ctx.operation != "echo" {
            return Ok(HandlerResult::error(
                STATUS_NOT_SUPPORTED,
                error_entity(
                    "unsupported_operation",
                    &format!("system/validate/echo: operation {:?} not supported", ctx.operation),
                ),
            ));
        }
        // Verbatim echo — clone the params entity through unmodified. No
        // decode/re-encode, so the §7a.1 byte-equality assertion holds.
        Ok(HandlerResult::ok(ctx.params.clone()))
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "validate/echo"
    }

    fn operations(&self) -> &[&str] {
        &["echo"]
    }
}

// ---------------------------------------------------------------------------
// DispatchOutboundHandler — §7a.1 outbound-seam-via-reentry (proves §6.13(b)).
// ---------------------------------------------------------------------------

/// `system/validate/dispatch-outbound` — operation `dispatch` originates
/// exactly one outbound EXECUTE via `ctx.execute_fn` (the §6.13(b) seam routed
/// through §6.11 reentry) to `operation@target`. The validator sets `target`
/// to itself, so the EXECUTE travels back over the same accepted connection
/// (B-role-same-connection per §7a.2a), where its `system/validate/echo`
/// serves the reentrant call. The downstream `{status, result}` is returned.
pub struct DispatchOutboundHandler {
    qualified_pattern: String,
}

impl DispatchOutboundHandler {
    pub fn new(local_peer_id: &str) -> Self {
        Self {
            qualified_pattern: qualify(local_peer_id, PATTERN_DISPATCH_OUTBOUND),
        }
    }

    async fn dispatch(&self, ctx: &HandlerContext) -> HandlerResult {
        // §6.13(b) seam must be wired (set by the connection dispatcher).
        let execute_fn = match ctx.execute_fn.as_ref() {
            Some(f) => f,
            None => {
                return HandlerResult::error(
                    STATUS_INTERNAL_ERROR,
                    error_entity(
                        "internal",
                        "dispatcher did not wire ctx.execute_fn (§6.13(b) seam missing)",
                    ),
                )
            }
        };

        // Text fields — no byte-fidelity concern.
        let data: ciborium::value::Value =
            match ciborium::from_reader(ctx.params.data.as_slice()) {
                Ok(v) => v,
                Err(e) => {
                    return HandlerResult::error(
                        STATUS_BAD_REQUEST,
                        error_entity(
                            "invalid_params",
                            &format!("decode dispatch-outbound params: {}", e),
                        ),
                    )
                }
            };
        let target = field_text(&data, "target");
        let operation = field_text(&data, "operation");
        if target.is_empty() || operation.is_empty() {
            return HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "invalid_params",
                    "dispatch-outbound requires target and operation",
                ),
            );
        }

        // §7a.2a in-band cap-passing: the three authority entities and the
        // opaque `value` ride nested in params as raw CBOR. Extract them with
        // byte fidelity — a decode+re-encode would break content-hash
        // recomputation and the verbatim echo round-trip.
        let cap_raw = entity_wire::cbor_map_field_raw(&ctx.params.data, "reentry_capability");
        let granter_raw = entity_wire::cbor_map_field_raw(&ctx.params.data, "reentry_granter");
        let sig_raw = entity_wire::cbor_map_field_raw(&ctx.params.data, "reentry_cap_signature");
        let (cap_raw, granter_raw, sig_raw) = match (cap_raw, granter_raw, sig_raw) {
            (Some(c), Some(g), Some(s)) => (c, g, s),
            _ => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "invalid_params",
                        "dispatch-outbound requires reentry_capability + reentry_granter + \
                         reentry_cap_signature in-band per §7a.2a",
                    ),
                )
            }
        };

        // Decode the authority entities byte-faithfully, then re-canonicalize
        // so each carries the right content_hash before dispatch (decode keeps
        // type+data; Entity::new recomputes the hash deterministically).
        let cap = match recanonicalize(cap_raw) {
            Ok(e) => e,
            Err(e) => return invalid("reentry_capability", &e),
        };
        let granter = match recanonicalize(granter_raw) {
            Ok(e) => e,
            Err(e) => return invalid("reentry_granter", &e),
        };
        let sig = match recanonicalize(sig_raw) {
            Ok(e) => e,
            Err(e) => return invalid("reentry_cap_signature", &e),
        };

        // The caller passed `value` as a raw-CBOR opaque payload; wrap it as a
        // primitive/any entity for the §3.4 "params is an entity" requirement.
        // Default an absent value to CBOR null.
        let value_raw = entity_wire::cbor_map_field_raw(&ctx.params.data, "value")
            .map(|s| s.to_vec())
            .unwrap_or_else(|| vec![0xf6]);
        let outbound_params = match Entity::new("primitive/any", value_raw) {
            Ok(e) => e,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_params", &format!("build outbound params entity: {}", e)),
                )
            }
        };

        // Originate one outbound EXECUTE through the §6.13(b) seam. The reentry
        // capability authorizes this EXECUTE (opts.capability); its granter
        // identity + signature ride in the envelope `included` via opts.included
        // (the in-band chain isn't in the local store, so collect_chain_bundle
        // can't reach it — this is the §7a.2a path).
        let opts = ExecuteOptions {
            capability: Some(cap),
            included: vec![granter, sig],
            ..Default::default()
        };
        let downstream = match execute_fn(target, operation, outbound_params, opts).await {
            Ok(r) => r,
            Err(e) => {
                return HandlerResult::error(
                    STATUS_BAD_GATEWAY,
                    error_entity(
                        "reentry_dispatch_failed",
                        &format!("originate reentry EXECUTE: {}", e),
                    ),
                )
            }
        };

        // Pack the downstream EXECUTE_RESPONSE into the §7a.1 result shape
        // {status, result}, wrapped as primitive/any. `result` is the
        // downstream result entity encoded canonically (raw-embedded so its
        // data byte-fidelity — and thus the echo round-trip — survives).
        let result_entity_bytes = entity_wire::encode_entity(&downstream.result);
        let mut out = Vec::new();
        out.push(0xA2); // CBOR map, 2 items
                        // ECF key order: "result" < "status" (equal length, lexicographic).
        entity_ecf::encode_cbor_text(&mut out, "result");
        out.extend_from_slice(&result_entity_bytes);
        entity_ecf::encode_cbor_text(&mut out, "status");
        out.extend_from_slice(&entity_ecf::to_ecf(&entity_ecf::integer(downstream.status as i64)));

        match Entity::new("primitive/any", out) {
            Ok(e) => HandlerResult::ok(e),
            Err(e) => HandlerResult::error(
                STATUS_INTERNAL_ERROR,
                error_entity("internal", &format!("build dispatch-outbound result: {}", e)),
            ),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for DispatchOutboundHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        if ctx.operation != "dispatch" {
            return Ok(HandlerResult::error(
                STATUS_NOT_SUPPORTED,
                error_entity(
                    "unsupported_operation",
                    &format!(
                        "system/validate/dispatch-outbound: operation {:?} not supported",
                        ctx.operation
                    ),
                ),
            ));
        }
        Ok(self.dispatch(ctx).await)
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "validate/dispatch-outbound"
    }

    fn operations(&self) -> &[&str] {
        &["dispatch"]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn field_text(data: &ciborium::value::Value, key: &str) -> String {
    data.as_map()
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .and_then(|(_, v)| v.as_text())
        })
        .unwrap_or("")
        .to_string()
}

/// Decode an entity-CBOR slice byte-faithfully, then re-canonicalize so its
/// content_hash is recomputed from `{type, data}`.
fn recanonicalize(raw: &[u8]) -> Result<Entity, String> {
    let decoded = entity_wire::decode_entity(raw).map_err(|e| e.to_string())?;
    let ty = decoded.entity_type;
    let data = decoded.data;
    Entity::new(&ty, data).map_err(|e| e.to_string())
}

fn invalid(field: &str, msg: &str) -> HandlerResult {
    HandlerResult::error(
        STATUS_BAD_REQUEST,
        error_entity("invalid_params", &format!("rebuild {}: {}", field, msg)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_handler::ExecuteFn;
    use std::sync::Arc;

    const PID: &str = "testpeer";

    fn ctx(op: &str, params: Entity) -> HandlerContext {
        HandlerContext::builder(execute_stub(), params)
            .operation(op)
            .build()
    }

    fn ctx_with_fn(op: &str, params: Entity) -> HandlerContext {
        // Dummy §6.13(b) seam — never reached on the error-branch tests, but
        // its presence distinguishes the 500 (no seam) path from the rest.
        let f: ExecuteFn = Arc::new(|_h, _o, _p, _opts| {
            Box::pin(async move { Ok(HandlerResult::ok(null_entity())) })
        });
        HandlerContext::builder(execute_stub(), params)
            .operation(op)
            .execute_fn(f)
            .build()
    }

    fn execute_stub() -> Entity {
        Entity::new("system/protocol/execute", vec![0xa0]).unwrap()
    }

    fn null_entity() -> Entity {
        Entity::new("primitive/any", vec![0xf6]).unwrap()
    }

    fn err_code(r: &HandlerResult) -> String {
        let v: ciborium::value::Value =
            ciborium::from_reader(r.result.data.as_slice()).unwrap();
        field_text(&v, "code")
    }

    /// params map carrying target + operation but no reentry-authority fields.
    fn dispatch_params_no_reentry() -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "target" => entity_ecf::text("entity://x/system/validate/echo"),
            "operation" => entity_ecf::text("echo")
        });
        Entity::new("primitive/any", data).unwrap()
    }

    #[tokio::test]
    async fn echo_returns_params_verbatim() {
        let h = EchoHandler::new(PID);
        // CBOR text "hi" = 0x62 'h' 'i'.
        let params = Entity::new("primitive/any", vec![0x62, b'h', b'i']).unwrap();
        let r = h.handle(&ctx("echo", params.clone())).await.unwrap();
        assert_eq!(r.status, 200);
        // Byte-exact: same content_hash AND same data bytes (no re-encode).
        assert_eq!(r.result.content_hash, params.content_hash);
        assert_eq!(r.result.data, params.data);
    }

    #[tokio::test]
    async fn echo_rejects_unknown_op() {
        let h = EchoHandler::new(PID);
        let r = h.handle(&ctx("ping", null_entity())).await.unwrap();
        assert_eq!(r.status, STATUS_NOT_SUPPORTED);
        assert_eq!(err_code(&r), "unsupported_operation");
    }

    #[tokio::test]
    async fn dispatch_rejects_unknown_op() {
        let h = DispatchOutboundHandler::new(PID);
        let r = h.handle(&ctx("nope", null_entity())).await.unwrap();
        assert_eq!(r.status, STATUS_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn dispatch_500_without_execute_fn() {
        let h = DispatchOutboundHandler::new(PID);
        // No execute_fn on the context → §6.13(b) seam missing.
        let r = h
            .handle(&ctx("dispatch", dispatch_params_no_reentry()))
            .await
            .unwrap();
        assert_eq!(r.status, STATUS_INTERNAL_ERROR);
        assert_eq!(err_code(&r), "internal");
    }

    #[tokio::test]
    async fn dispatch_400_missing_reentry_fields() {
        let h = DispatchOutboundHandler::new(PID);
        let r = h
            .handle(&ctx_with_fn("dispatch", dispatch_params_no_reentry()))
            .await
            .unwrap();
        assert_eq!(r.status, STATUS_BAD_REQUEST);
        assert_eq!(err_code(&r), "invalid_params");
    }

    #[tokio::test]
    async fn dispatch_400_missing_target() {
        let h = DispatchOutboundHandler::new(PID);
        // Empty params map → no target/operation.
        let params = Entity::new("primitive/any", vec![0xa0]).unwrap();
        let r = h.handle(&ctx_with_fn("dispatch", params)).await.unwrap();
        assert_eq!(r.status, STATUS_BAD_REQUEST);
        assert_eq!(err_code(&r), "invalid_params");
    }
}
