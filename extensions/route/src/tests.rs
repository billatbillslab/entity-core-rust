//! EXTENSION-ROUTE v1.0 unit tests — the §3 match + the §2 entity codec.
//!
//! Mirrors the cohort's Go-authored `route` vectors (ROUTE §7.2): exact-forward,
//! default-route, metric-tiebreak, expired-skip, no-route, deliver-action,
//! exact-beats-default — plus codec round-trip + canonical path + the §2
//! cross-field-invariant skips.

use super::*;

const DEST: &str = "z6MkDestination";
const VIA1: &str = "z6MkViaOne";
const VIA2: &str = "z6MkViaTwo";

fn forward(match_dest: &str, via: &str, metric: u32) -> RouteData {
    RouteData {
        match_dest: match_dest.into(),
        action: ROUTE_ACTION_FORWARD.into(),
        via: Some(via.into()),
        metric,
        expires_at: 0,
    }
}

fn deliver(match_dest: &str) -> RouteData {
    RouteData {
        match_dest: match_dest.into(),
        action: ROUTE_ACTION_DELIVER.into(),
        via: None,
        metric: 0,
        expires_at: 0,
    }
}

// --- ROUTE-EXACT-1 — exact match → forward to via. ---------------------------
#[test]
fn exact_forward() {
    let routes = vec![forward(DEST, VIA1, 0)];
    assert_eq!(
        resolve(&routes, DEST, 1000),
        Some(RouteResolution::Forward(VIA1.into()))
    );
}

// --- ROUTE-DEFAULT-1 — `*` default route resolves when no exact. -------------
#[test]
fn default_route() {
    let routes = vec![forward(ROUTE_MATCH_DEFAULT, VIA1, 0)];
    assert_eq!(
        resolve(&routes, DEST, 1000),
        Some(RouteResolution::Forward(VIA1.into()))
    );
}

// --- ROUTE-METRIC-TIEBREAK-1 — lowest metric wins within a cohort. -----------
#[test]
fn metric_tiebreak() {
    // Two exact routes; the lower metric (VIA2 @ 1) beats VIA1 @ 5.
    let routes = vec![forward(DEST, VIA1, 5), forward(DEST, VIA2, 1)];
    assert_eq!(
        resolve(&routes, DEST, 1000),
        Some(RouteResolution::Forward(VIA2.into()))
    );
    // Order-independence: same outcome if listed the other way.
    let routes = vec![forward(DEST, VIA2, 1), forward(DEST, VIA1, 5)];
    assert_eq!(
        resolve(&routes, DEST, 1000),
        Some(RouteResolution::Forward(VIA2.into()))
    );
}

// --- ROUTE-EXACT-BEATS-DEFAULT-1 — exact outranks `*` even at higher metric. -
#[test]
fn exact_beats_default() {
    // Default route has the better metric (0); exact still wins (longest-match).
    let routes = vec![forward(ROUTE_MATCH_DEFAULT, VIA1, 0), forward(DEST, VIA2, 100)];
    assert_eq!(
        resolve(&routes, DEST, 1000),
        Some(RouteResolution::Forward(VIA2.into()))
    );
}

// --- ROUTE-EXPIRED-SKIP-1 — past expires_at is skipped (not surfaced). -------
#[test]
fn expired_skipped() {
    let mut r = forward(DEST, VIA1, 0);
    r.expires_at = 500; // past relative to now=1000
    assert_eq!(resolve(&[r], DEST, 1000), None);

    // A future expiry still matches; 0 == null never expires.
    let mut future = forward(DEST, VIA1, 0);
    future.expires_at = 5000;
    assert_eq!(
        resolve(&[future], DEST, 1000),
        Some(RouteResolution::Forward(VIA1.into()))
    );
}

// --- ROUTE-NOROUTE-1 — no matching entry → None (relay → no_route/502). ------
#[test]
fn no_route() {
    let routes = vec![forward("z6MkSomeoneElse", VIA1, 0)];
    assert_eq!(resolve(&routes, DEST, 1000), None);
    assert_eq!(resolve(&[], DEST, 1000), None);
}

// --- ROUTE-DELIVER-1 — action=deliver → terminal at this relay. --------------
#[test]
fn deliver_action() {
    assert_eq!(resolve(&[deliver(DEST)], DEST, 1000), Some(RouteResolution::Deliver));
    // Default-token deliver also resolves terminal.
    assert_eq!(
        resolve(&[deliver(ROUTE_MATCH_DEFAULT)], DEST, 1000),
        Some(RouteResolution::Deliver)
    );
}

// --- §2 cross-field invariant — invalid routes never match. ------------------
#[test]
fn forward_without_via_skipped() {
    let r = RouteData {
        match_dest: DEST.into(),
        action: ROUTE_ACTION_FORWARD.into(),
        via: None, // forward REQUIRES via
        metric: 0,
        expires_at: 0,
    };
    assert_eq!(resolve(&[r], DEST, 1000), None);
}

#[test]
fn deliver_with_via_skipped() {
    let r = RouteData {
        match_dest: DEST.into(),
        action: ROUTE_ACTION_DELIVER.into(),
        via: Some(VIA1.into()), // deliver REQUIRES empty via
        metric: 0,
        expires_at: 0,
    };
    assert_eq!(resolve(&[r], DEST, 1000), None);
}

#[test]
fn unknown_action_skipped() {
    let r = RouteData {
        match_dest: DEST.into(),
        action: "teleport".into(),
        via: Some(VIA1.into()),
        metric: 0,
        expires_at: 0,
    };
    assert_eq!(resolve(&[r], DEST, 1000), None);
}

// --- §2 entity codec — round-trip + omitempty + canonical path. --------------
#[test]
fn entity_round_trip() {
    let r = forward(DEST, VIA1, 7);
    let entity = r.to_entity().unwrap();
    assert_eq!(entity.entity_type, TYPE_ROUTE);
    assert_eq!(RouteData::from_entity(&entity).unwrap(), r);

    // Minimal deliver route: via/metric/expires_at all absent (omitempty).
    let d = deliver(DEST);
    let de = d.to_entity().unwrap();
    let decoded = decode_map(&de.data).unwrap();
    assert!(get_field(&decoded, "via").is_none());
    assert!(get_field(&decoded, "metric").is_none());
    assert!(get_field(&decoded, "expires_at").is_none());
    assert_eq!(RouteData::from_entity(&de).unwrap(), d);
}

#[test]
fn canonical_path_is_hex_of_canonical_bytes() {
    let entity = forward(DEST, VIA1, 0).to_entity().unwrap();
    let path = route_path(&entity.content_hash);
    assert!(path.starts_with("system/route/"));
    let hex = path.strip_prefix("system/route/").unwrap();
    // SHA-256 canonical form = 1 algorithm byte + 32 digest = 33 bytes = 66 hex
    // chars (NOT 130 — the padded-digest trap #1).
    assert_eq!(hex.len(), 66, "expected canonical 33-byte hex, got {}", hex);
    assert_eq!(hex, entity.content_hash.to_hex());
}
