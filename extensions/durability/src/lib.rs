//! Durability contract (EXTENSION-DURABILITY v0.1, extracted from
//! EXTENSION-INBOX §10).
//!
//! **Status:** the spec is EXPLORATORY / OPTIONAL / NOT ACTIVELY DEVELOPED.
//! V7 v7.46 has no durability material; if EXTENSION-DURABILITY is installed
//! it reintroduces 412 (and the durability use of 202) *within its own
//! surface only*. A peer that does not implement durability is conformant
//! against V7 v7.46. This Rust peer ships the contract anyway — the wire
//! shape is preserved verbatim from the v7.47 / v5.7 + Amendment 1 design.
//!
//! The verdict is a status code plus a pinned `system/durability-result`
//! field:
//!
//! - **200** — the durability outcome is final; nothing to watch.
//! - **202** — accepted; the `committed` strength completes asynchronously and
//!   is observable at the receiver-returned handle (§6).
//! - **412** — a *required* durability precondition could not be met; the
//!   operation was **not performed** (refused at acceptance, safe to retry).
//!
//! Invariant (§5): `applied` is the durability *physically in place at the
//! moment of the response* — one meaning everywhere, never a promise. A
//! promise lives only in `committed`, gated to status 202.
//!
//! This peer self-determines `none`/`stored` from its store configuration.
//! `replicated` is a replication-class strength this peer is not configured
//! for (no replication topology exists here), so a *required* replication
//! request is refused with 412 per §5 row 4 ("not configured for the
//! required topology"); a best-effort one takes less, observably. The
//! strength vocabulary is illustrative, not a frozen enum (§7).

use entity_entity::Entity;

/// reason code spellings — pinned by EXTENSION-DURABILITY §5/§7 (the
/// spec-enumerated cases use pinned spellings; §7's "implementation-defined"
/// carve-out applies to strength-level vocabulary, not reason codes).
pub const REASON_NO_DURABLE_STORE: &str = "no_durable_store";
pub const REASON_REQUIRED_UNMET: &str = "durability_required_unmet";
/// §5/§8 fail-closed reason — the requested level is not in the receiver's
/// recognized vocabulary; never promise what you don't understand.
pub const REASON_UNKNOWN_LEVEL: &str = "unknown_level";
/// §5/§8 — `(author, request_id)` matched a previously preserved entry; the
/// receiver enforces uniqueness over the pair, returns 409, prior handle echoed.
pub const REASON_DUPLICATE_REQUEST_ID: &str = "duplicate_request_id";

/// A durability strength level (§7 — values illustrative, not frozen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurabilityLevel {
    /// Nothing physically in place (e.g. an in-memory store).
    None,
    /// Written to a durable store; survives restart.
    Stored,
    /// Replicated to other peers (replication-class, not self-certifiable
    /// at acceptance by this peer).
    Replicated,
    /// An unrecognized strength string — not self-certifiable.
    Unknown(String),
}

impl DurabilityLevel {
    pub fn parse(s: &str) -> Self {
        match s {
            "none" => Self::None,
            "stored" => Self::Stored,
            "replicated" => Self::Replicated,
            other => Self::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Stored => "stored",
            Self::Replicated => "replicated",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Numeric strength for ordering. `Unknown` sits above all known levels —
    /// it cannot be certified, so it can never be "met".
    fn rank(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Stored => 1,
            Self::Replicated => 2,
            Self::Unknown(_) => u8::MAX,
        }
    }

    /// True when this peer can certify the level synchronously at acceptance
    /// from its own configuration (§4). Replication-class and unknown
    /// strengths are not self-certifiable here.
    fn self_determinable(&self) -> bool {
        matches!(self, Self::None | Self::Stored)
    }
}

/// Receiver durability policy (§4) — the max strength this peer can
/// physically guarantee from its own store configuration. Implementation-
/// defined per §8; defaults to `None` (no durable store, e.g. an in-memory
/// store). Persistent stores (SQLite/OPFS) set `Stored`.
#[derive(Debug, Clone)]
pub struct DurabilityPolicy {
    pub max_self_determinable: DurabilityLevel,
}

impl Default for DurabilityPolicy {
    fn default() -> Self {
        Self {
            // An in-memory `ContentStore` + `LocationIndex` satisfies §5's
            // "physically in place, findable via the response's `handle`" for
            // the session; survival across process restart is not in the §5
            // contract (that's persistence, a separate substrate dimension —
            // §1 / §3 zone characteristics). Matches Go's
            // `DefaultDurabilityPolicy()` in
            // `entity-core-go/core/protocol/durability.go`. Builders backed by
            // SQLite/OPFS keep this; the constructors do not override.
            max_self_determinable: DurabilityLevel::Stored,
        }
    }
}

/// Parsed request-side durability marker (§2).
#[derive(Debug, Clone)]
pub struct DurabilityRequest {
    pub level: String,
    /// §2 — default false. false = best-effort (take less, observably).
    /// true = required (refuse if unmet, §5).
    pub must_have: bool,
}

/// The pinned `system/durability-result` verdict body (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityResult {
    pub requested: String,
    /// Durability PHYSICALLY IN PLACE at response time, or `"none"`. Never a
    /// promise (§5 invariant).
    pub applied: String,
    /// A strength committed to a pathway that completes asynchronously.
    /// Present ONLY with status 202.
    pub committed: Option<String>,
    /// The best the receiver could offer. Present ONLY with status 412.
    pub max_available: Option<String>,
    pub reason: Option<String>,
    /// Absolute tree path where the durable entry can be read. Present when
    /// `applied != none` (the receiver wrote it; sender reaches it via
    /// `tree:get` / sync / subscription). On 202, names where the committed
    /// entry will land — may resolve to 404 until commit completes. The
    /// receiver chooses the storage layout. EXTENSION-DURABILITY §6 /
    /// Amendment 1.
    pub handle: Option<String>,
}

impl DurabilityResult {
    /// Encode as the CBOR map value for the EXECUTE_RESPONSE `durability`
    /// field. The wire convention for typed-struct fields is a bare CBOR
    /// map of the field set (same as `system/delivery-spec` under
    /// `deliver_to` and `system/bounds` under `bounds`) — NOT a
    /// `{type, data, content_hash}` entity wrapper. Optional fields are
    /// absent when `None` (interop: optional fields SHOULD be absent, not
    /// null). ECF canonicalizes the map key order.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut fields = vec![
            (
                entity_ecf::text("requested"),
                entity_ecf::text(&self.requested),
            ),
            (entity_ecf::text("applied"), entity_ecf::text(&self.applied)),
        ];
        if let Some(c) = &self.committed {
            fields.push((entity_ecf::text("committed"), entity_ecf::text(c)));
        }
        if let Some(m) = &self.max_available {
            fields.push((entity_ecf::text("max_available"), entity_ecf::text(m)));
        }
        if let Some(r) = &self.reason {
            fields.push((entity_ecf::text("reason"), entity_ecf::text(r)));
        }
        if let Some(h) = &self.handle {
            fields.push((entity_ecf::text("handle"), entity_ecf::text(h)));
        }
        entity_ecf::to_ecf(&entity_ecf::Value::Map(fields))
    }
}

/// The durability verdict: status + the pinned result body (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityVerdict {
    /// 200 (final), 202 (committed, async), or 412 (refused — operation NOT
    /// performed).
    pub status: u32,
    pub result: DurabilityResult,
}

impl DurabilityVerdict {
    /// 412 — the operation MUST NOT be performed (refused at acceptance).
    pub fn refused(&self) -> bool {
        self.status == entity_handler::STATUS_PRECONDITION_FAILED
    }

    /// True when the verdict's `applied` level claims durable storage
    /// (`stored` or higher), meaning the originating EXECUTE MUST be
    /// physically written into the inbox namespace at `(author, request_id)`
    /// for the claim to be honest (§5 invariant; §6 lookup).
    pub fn preserve(&self) -> bool {
        DurabilityLevel::parse(&self.result.applied).rank()
            >= DurabilityLevel::Stored.rank()
    }
}

/// Reconcile a durability request against the receiver's policy at acceptance
/// (§4), producing the §5 verdict.
///
/// `async_pathway` is true when the request carries `deliver_to`: the durable
/// inbox write completes asynchronously, so nothing is physically in place at
/// response time (`applied` = `none`) and a met strength is reported as a
/// `committed` promise with status 202, observable at `(author, request_id)`
/// (§6). When false (synchronous request), the durability achieved by the
/// store is physically in place at response time and is reported in `applied`
/// with status 200.
pub fn reconcile(
    req: &DurabilityRequest,
    policy: &DurabilityPolicy,
    async_pathway: bool,
) -> DurabilityVerdict {
    let requested = DurabilityLevel::parse(&req.level);
    let pmax = &policy.max_self_determinable;
    let requested_str = req.level.clone();

    // EXTENSION-DURABILITY §5/§8 — unknown-level fail-closed. Never promise
    // what you don't understand. Must come BEFORE the met/unmet branches so
    // a recognised-but-unsupported "weaker take-less" path can't accidentally
    // claim certification of an unrecognised level. Matches Go's
    // `levelUnknown` arm in core/protocol/durability.go.
    if matches!(requested, DurabilityLevel::Unknown(_)) {
        if req.must_have {
            let max_available = if pmax.rank() > DurabilityLevel::None.rank() {
                pmax.as_str().to_string()
            } else {
                "none".to_string()
            };
            return DurabilityVerdict {
                status: entity_handler::STATUS_PRECONDITION_FAILED,
                result: DurabilityResult {
                    requested: requested_str,
                    applied: "none".to_string(),
                    committed: None,
                    max_available: Some(max_available),
                    reason: Some(REASON_UNKNOWN_LEVEL.to_string()),
                    handle: None,
                },
            };
        }
        return verdict_200(DurabilityResult {
            requested: requested_str,
            applied: "none".to_string(),
            committed: None,
            max_available: None,
            reason: Some(REASON_UNKNOWN_LEVEL.to_string()),
            handle: None,
        });
    }

    // Can this peer self-certify the requested level from its own config?
    let met = requested.self_determinable() && requested.rank() <= pmax.rank();

    if met {
        // The receiver can do ≥ requested.
        if async_pathway {
            // The durable write completes asynchronously (inbox). Nothing is
            // physically in place at response time.
            if requested.rank() >= DurabilityLevel::Stored.rank() {
                return verdict_202(DurabilityResult {
                    requested: requested_str.clone(),
                    applied: "none".to_string(),
                    committed: Some(requested_str),
                    max_available: None,
                    reason: None,
                    handle: None,
                });
            }
            // requested == none: no durability to commit to. Still an async
            // inbox acknowledgement.
            return verdict_202(DurabilityResult {
                requested: requested_str.clone(),
                applied: "none".to_string(),
                committed: None,
                max_available: None,
                reason: None,
                handle: None,
            });
        }
        // Synchronous: the achieved durability is physically in place now.
        return verdict_200(DurabilityResult {
            requested: requested_str.clone(),
            applied: requested_str,
            committed: None,
            max_available: None,
            reason: None,
            handle: None,
        });
    }

    // Not met: requested is replication-class, or stronger than the policy
    // can self-determine. (Unknown levels handled above.)
    if req.must_have {
        // Required durability cannot be met → refuse at acceptance. The
        // operation is NOT performed (safe to retry elsewhere).
        let max_available = if pmax.rank() > DurabilityLevel::None.rank() {
            pmax.as_str().to_string()
        } else {
            "none".to_string()
        };
        return DurabilityVerdict {
            status: entity_handler::STATUS_PRECONDITION_FAILED,
            result: DurabilityResult {
                requested: requested_str,
                applied: "none".to_string(),
                committed: None,
                max_available: Some(max_available),
                reason: Some(REASON_REQUIRED_UNMET.to_string()),
                handle: None,
            },
        };
    }

    // Best-effort: take less, observably.
    let no_durable_store = pmax.rank() == DurabilityLevel::None.rank();
    if async_pathway {
        if no_durable_store {
            return verdict_202(DurabilityResult {
                requested: requested_str,
                applied: "none".to_string(),
                committed: None,
                max_available: None,
                reason: Some(REASON_NO_DURABLE_STORE.to_string()),
                handle: None,
            });
        }
        return verdict_202(DurabilityResult {
            requested: requested_str,
            applied: "none".to_string(),
            committed: Some(pmax.as_str().to_string()),
            max_available: None,
            reason: None,
            handle: None,
        });
    }
    if no_durable_store {
        return verdict_200(DurabilityResult {
            requested: requested_str,
            applied: "none".to_string(),
            committed: None,
            max_available: None,
            reason: Some(REASON_NO_DURABLE_STORE.to_string()),
            handle: None,
        });
    }
    verdict_200(DurabilityResult {
        requested: requested_str,
        applied: pmax.as_str().to_string(),
        committed: None,
        max_available: None,
        reason: None,
        handle: None,
    })
}

fn verdict_200(result: DurabilityResult) -> DurabilityVerdict {
    DurabilityVerdict {
        status: entity_handler::STATUS_OK,
        result,
    }
}

fn verdict_202(result: DurabilityResult) -> DurabilityVerdict {
    DurabilityVerdict {
        status: entity_handler::STATUS_ACCEPTED,
        result,
    }
}

/// Extract the request-side durability marker (§2) from an EXECUTE entity's
/// data. Encoded inline as a nested CBOR map under `durability_request`, the
/// same convention as `deliver_to`.
pub fn extract_durability_request(execute: &Entity) -> Option<DurabilityRequest> {
    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("durability_request") {
            let dr = v.as_map()?;
            let mut level = None;
            let mut must_have = false;
            for (dk, dv) in dr {
                match dk.as_text() {
                    Some("level") => level = dv.as_text().map(|s| s.to_string()),
                    Some("must_have") => must_have = dv.as_bool().unwrap_or(false),
                    _ => {}
                }
            }
            return level.map(|level| DurabilityRequest { level, must_have });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(level: &str, must_have: bool) -> DurabilityRequest {
        DurabilityRequest {
            level: level.to_string(),
            must_have,
        }
    }

    fn policy(max: DurabilityLevel) -> DurabilityPolicy {
        DurabilityPolicy {
            max_self_determinable: max,
        }
    }

    // §5 row 1: receiver can do ≥ X (sync) → 200 {requested:X, applied:X}.
    #[test]
    fn row1_can_meet_sync() {
        let v = reconcile(&req("stored", false), &policy(DurabilityLevel::Stored), false);
        assert_eq!(v.status, 200);
        assert_eq!(v.result.applied, "stored");
        assert_eq!(v.result.requested, "stored");
        assert!(v.result.committed.is_none());
        assert!(v.result.max_available.is_none());
        assert!(v.result.reason.is_none());
    }

    // §5 row 2: weaker Y, not must-have (sync) → 200 {requested:X, applied:Y}.
    #[test]
    fn row2_weaker_best_effort_sync() {
        let v = reconcile(
            &req("replicated", false),
            &policy(DurabilityLevel::Stored),
            false,
        );
        assert_eq!(v.status, 200);
        assert_eq!(v.result.requested, "replicated");
        assert_eq!(v.result.applied, "stored");
        assert!(v.result.committed.is_none());
        assert!(v.result.reason.is_none());
    }

    // §5 row 3: no durable store, not must-have (sync) →
    // 200 {applied:none, reason:no_durable_store}.
    #[test]
    fn row3_no_durable_store_sync() {
        let v = reconcile(&req("stored", false), &policy(DurabilityLevel::None), false);
        assert_eq!(v.status, 200);
        assert_eq!(v.result.applied, "none");
        assert_eq!(v.result.reason.as_deref(), Some(REASON_NO_DURABLE_STORE));
        assert!(v.result.committed.is_none());
        assert!(v.result.max_available.is_none());
    }

    // §5 row 4: must-have, cannot meet → 412 {applied:none,
    // max_available:Y|none, reason:durability_required_unmet}, NOT performed.
    #[test]
    fn row4_must_have_unmet_refused() {
        let v = reconcile(&req("stored", true), &policy(DurabilityLevel::None), false);
        assert_eq!(v.status, 412);
        assert!(v.refused());
        assert_eq!(v.result.applied, "none");
        assert_eq!(v.result.max_available.as_deref(), Some("none"));
        assert_eq!(v.result.reason.as_deref(), Some(REASON_REQUIRED_UNMET));
        assert!(v.result.committed.is_none());
    }

    #[test]
    fn row4_must_have_unmet_reports_max_available() {
        let v = reconcile(
            &req("replicated", true),
            &policy(DurabilityLevel::Stored),
            false,
        );
        assert_eq!(v.status, 412);
        assert_eq!(v.result.max_available.as_deref(), Some("stored"));
        assert_eq!(v.result.reason.as_deref(), Some(REASON_REQUIRED_UNMET));
    }

    // §5 row 5: configured-for, completes later (async inbox pathway) →
    // 202 {applied:none, committed:X}.
    #[test]
    fn row5_async_committed() {
        let v = reconcile(&req("stored", false), &policy(DurabilityLevel::Stored), true);
        assert_eq!(v.status, 202);
        assert_eq!(v.result.applied, "none");
        assert_eq!(v.result.committed.as_deref(), Some("stored"));
        assert!(v.result.max_available.is_none());
    }

    // Required durability via async pathway that CAN meet it → 202 committed
    // (not 412): "required" means the sender verifies it landed (§6).
    #[test]
    fn must_have_async_can_meet_is_202_not_412() {
        let v = reconcile(&req("stored", true), &policy(DurabilityLevel::Stored), true);
        assert_eq!(v.status, 202);
        assert_eq!(v.result.committed.as_deref(), Some("stored"));
        assert!(!v.refused());
    }

    // Best-effort async, weaker policy → 202 committed at the weaker level.
    #[test]
    fn best_effort_async_weaker() {
        let v = reconcile(
            &req("replicated", false),
            &policy(DurabilityLevel::Stored),
            true,
        );
        assert_eq!(v.status, 202);
        assert_eq!(v.result.committed.as_deref(), Some("stored"));
    }

    // Best-effort async, no durable store → 202, no committed, reason set.
    #[test]
    fn best_effort_async_no_store() {
        let v = reconcile(&req("stored", false), &policy(DurabilityLevel::None), true);
        assert_eq!(v.status, 202);
        assert!(v.result.committed.is_none());
        assert_eq!(v.result.reason.as_deref(), Some(REASON_NO_DURABLE_STORE));
    }

    // Required replication when this peer is not configured for replication
    // → 412 (§5 row 4: "not configured for the required topology").
    #[test]
    fn required_replication_not_configured_refused() {
        let v = reconcile(
            &req("replicated", true),
            &policy(DurabilityLevel::Stored),
            true,
        );
        assert_eq!(v.status, 412);
        assert!(v.refused());
    }

    // §5/§8 — unknown level, must_have → 412 with reason:unknown_level
    // (NOT durability_required_unmet — the receiver's vocabulary didn't
    // recognize the requested string, distinct from a recognized-but-too-strong
    // level).
    #[test]
    fn unknown_level_must_have_refused() {
        let v = reconcile(
            &req("quantum-entangled", true),
            &policy(DurabilityLevel::Stored),
            false,
        );
        assert_eq!(v.status, 412);
        assert_eq!(v.result.reason.as_deref(), Some(REASON_UNKNOWN_LEVEL));
        assert_eq!(v.result.max_available.as_deref(), Some("stored"));
    }

    // §5/§8 — unknown level, best-effort → fail-closed: 200 applied:none,
    // reason:unknown_level. NEVER take-less by silently downgrading to
    // policy_max, since that would be claiming we certified a level we don't
    // understand. Matches Go's `levelUnknown` arm.
    #[test]
    fn unknown_level_best_effort_fail_closed() {
        let v = reconcile(
            &req("quantum-entangled", false),
            &policy(DurabilityLevel::Stored),
            false,
        );
        assert_eq!(v.status, 200);
        assert_eq!(v.result.applied, "none");
        assert_eq!(v.result.requested, "quantum-entangled");
        assert_eq!(v.result.reason.as_deref(), Some(REASON_UNKNOWN_LEVEL));
        assert!(v.result.handle.is_none());
    }

    // Invariant: committed only ever appears with 202; max_available only
    // with 412; applied never overstates.
    #[test]
    fn invariant_committed_and_max_available_gating() {
        for (level, must, max, async_p) in [
            ("none", false, DurabilityLevel::None, false),
            ("stored", false, DurabilityLevel::Stored, false),
            ("stored", true, DurabilityLevel::None, false),
            ("replicated", false, DurabilityLevel::Stored, true),
            ("stored", true, DurabilityLevel::Stored, true),
            ("zzz", true, DurabilityLevel::Stored, true),
        ] {
            let v = reconcile(&req(level, must), &policy(max), async_p);
            if v.result.committed.is_some() {
                assert_eq!(v.status, 202, "committed only with 202 ({level})");
            }
            if v.result.max_available.is_some() {
                assert_eq!(v.status, 412, "max_available only with 412 ({level})");
            }
            if v.status != 202 {
                assert!(
                    v.result.committed.is_none(),
                    "non-202 must not promise ({level})"
                );
            }
        }
    }

    // §6 — `preserve()` selects the verdicts that MUST write-ahead persist
    // the originating EXECUTE into the inbox namespace so `applied` is honest.
    #[test]
    fn preserve_true_only_when_applied_at_least_stored() {
        // Row 1: sync, met, applied=stored → preserve.
        let v = reconcile(&req("stored", false), &policy(DurabilityLevel::Stored), false);
        assert!(v.preserve(), "applied=stored MUST preserve");

        // Row 3: no durable store, applied=none → no preservation.
        let v = reconcile(&req("stored", false), &policy(DurabilityLevel::None), false);
        assert!(!v.preserve(), "applied=none MUST NOT preserve");

        // Row 5 / async path: applied=none (committed promises stored, but the
        // write hasn't happened yet at response time) → dispatcher-level
        // preservation is the inbox handler's job, not this verdict's.
        let v = reconcile(&req("stored", false), &policy(DurabilityLevel::Stored), true);
        assert!(
            !v.preserve(),
            "async pathway: applied=none, dispatcher MUST NOT double-preserve"
        );

        // 412 refusal: applied=none → no preservation (op not performed).
        let v = reconcile(&req("stored", true), &policy(DurabilityLevel::None), false);
        assert!(!v.preserve(), "412 refusal MUST NOT preserve");
    }

    #[test]
    fn extract_durability_request_parses_inline_map() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("operation"), entity_ecf::text("put")),
            (
                entity_ecf::text("durability_request"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("level"), entity_ecf::text("stored")),
                    (entity_ecf::text("must_have"), entity_ecf::Value::Bool(true)),
                ]),
            ),
        ]));
        let e = Entity::new("system/protocol/execute", data).unwrap();
        let dr = extract_durability_request(&e).unwrap();
        assert_eq!(dr.level, "stored");
        assert!(dr.must_have);
    }

    #[test]
    fn extract_durability_request_absent() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("operation"),
            entity_ecf::text("get"),
        )]));
        let e = Entity::new("system/protocol/execute", data).unwrap();
        assert!(extract_durability_request(&e).is_none());
    }

    #[test]
    fn extract_durability_request_default_must_have_false() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("durability_request"),
            entity_ecf::Value::Map(vec![(
                entity_ecf::text("level"),
                entity_ecf::text("replicated"),
            )]),
        )]));
        let e = Entity::new("system/protocol/execute", data).unwrap();
        let dr = extract_durability_request(&e).unwrap();
        assert_eq!(dr.level, "replicated");
        assert!(!dr.must_have);
    }

    // The wire shape is a bare CBOR map of the field set (same convention
    // as `deliver_to`/`bounds`), NOT a `{type, data, content_hash}` entity
    // wrapper — that was the v7.47 / pre-extraction cross-impl validator
    // finding (now part of EXTENSION-DURABILITY's pinned shape).
    #[test]
    fn to_cbor_emits_bare_map_with_populated_fields() {
        let r = DurabilityResult {
            requested: "replicated".to_string(),
            applied: "none".to_string(),
            committed: None,
            max_available: Some("stored".to_string()),
            reason: Some(REASON_REQUIRED_UNMET.to_string()),
            handle: None,
        };
        let bytes = r.to_cbor();
        let val: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let m = val.as_map().expect("durability value must be a CBOR map");
        let field = |name: &str| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .and_then(|(_, v)| v.as_text())
                .map(|s| s.to_string())
        };
        assert_eq!(field("requested").as_deref(), Some("replicated"));
        assert_eq!(field("applied").as_deref(), Some("none"));
        assert_eq!(field("max_available").as_deref(), Some("stored"));
        assert_eq!(field("reason").as_deref(), Some("durability_required_unmet"));
        assert!(
            m.iter().all(|(k, _)| k.as_text() != Some("committed")),
            "absent optionals must not be encoded"
        );
        assert!(
            m.iter().all(|(k, _)| k.as_text() != Some("type")
                && k.as_text() != Some("data")
                && k.as_text() != Some("content_hash")),
            "wire shape MUST be the bare struct, never an entity wrapper"
        );
    }
}
