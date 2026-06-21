//! Capability tokens, grants, pattern matching, scope checking.
//!
//! Implements the 4D grant model from Entity Core Protocol v7.9 §3.6, §5.4:
//! - handlers (path-scope): which handlers can be called
//! - resources (path-scope): which data paths can be accessed
//! - operations (id-scope): which operations are authorized
//! - peers (id-scope, optional): which peers the grant applies to
//!
//! Pattern matching follows §5.4: `*` matches everything, `prefix/*` matches
//! subtrees, `/*/pattern` is a peer wildcard. All paths are absolute after
//! canonicalization (leading `/`).

use entity_hash::Hash;
use thiserror::Error;

mod mint;
pub use mint::{mint_reattenuated, MintError};

/// Policy-table fallback segment (V7.62 §6.2 closeout F8 — was `*` in
/// v7.62; renamed to the literal `default` to remove the glyph collision
/// with `*`-as-glob everywhere else in V7). Lives in `core/capability`
/// (not the optional handler crate) so the §4.4 connection-time policy
/// reader in `core/peer` can share the same constant without taking on a
/// feature-gated dependency.
pub const POLICY_FALLBACK_SEGMENT: &str = "default";

// ---------------------------------------------------------------------------
// Scope types (§3.6)
// ---------------------------------------------------------------------------

/// Path-based scope for handlers and resources.
///
/// `include` patterns define what's allowed, `exclude` patterns carve out exceptions.
/// Pattern syntax: `*` = all, `prefix/*` = subtree, `*/rest` = any peer.
#[derive(Debug, Clone, PartialEq)]
pub struct PathScope {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl PathScope {
    pub fn new(include: Vec<String>) -> Self {
        Self {
            include,
            exclude: Vec::new(),
        }
    }

    pub fn with_exclude(include: Vec<String>, exclude: Vec<String>) -> Self {
        Self { include, exclude }
    }

    /// Wildcard scope matching everything.
    pub fn all() -> Self {
        Self::new(vec!["*".into()])
    }

    /// Empty scope matching nothing (valid for resource-less handlers).
    pub fn none() -> Self {
        Self::new(vec![])
    }
}

/// Identifier-based scope for operations and peers.
///
/// Same include/exclude semantics as PathScope but for identifiers.
#[derive(Debug, Clone, PartialEq)]
pub struct IdScope {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl IdScope {
    pub fn new(include: Vec<String>) -> Self {
        Self {
            include,
            exclude: Vec::new(),
        }
    }

    pub fn with_exclude(include: Vec<String>, exclude: Vec<String>) -> Self {
        Self { include, exclude }
    }

    pub fn all() -> Self {
        Self::new(vec!["*".into()])
    }
}

/// A single grant entry covering all four dimensions (§3.6).
///
/// All four dimensions must match simultaneously within the same grant entry
/// for authorization to succeed.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantEntry {
    pub handlers: PathScope,
    pub resources: PathScope,
    pub operations: IdScope,
    /// When None, defaults to `{include: [local_peer_id]}` — local peer only.
    pub peers: Option<IdScope>,
    /// Domain-specific narrowing fields (map_of: primitive/any).
    /// Each key is a named restriction. Absent = unconstrained.
    /// During delegation: child MUST retain all parent constraint keys (§5.6).
    pub constraints: Option<std::collections::BTreeMap<String, ciborium::Value>>,
    /// Domain-specific expanding fields (map_of: primitive/any).
    /// Each key is a named privilege. Absent = most restricted.
    /// During delegation: child MUST NOT add keys parent doesn't have (§5.6).
    pub allowances: Option<std::collections::BTreeMap<String, ciborium::Value>>,
}

/// Default connection grants per §4.4.
///
/// Two grants:
/// 1. Tree handler: read type definitions and handler manifests.
/// 2. Capability handler: request capabilities (V7 §6.2).
///
/// Both targets are registered as bootstrap handlers when the matching
/// feature flag is on (default). Per RULING-CAPABILITY-HANDLER-
/// ADVERTISEMENT, an advertised grant SHALL only reference
/// handlers registered on this peer — keep these in sync with the
/// `capability-handler` and `handlers` feature gates in core/peer.
pub fn default_connection_grants() -> Vec<GrantEntry> {
    vec![
        GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec![
                "system/type/*".into(),
                "system/handler/*".into(),
            ]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        },
        GrantEntry {
            handlers: PathScope::new(vec!["system/capability".into()]),
            resources: PathScope::new(vec![]),
            operations: IdScope::new(vec!["request".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        },
    ]
}

/// Wide-open connection grants for debugging/testing.
///
/// Single grant covering all handlers, all resources, all operations,
/// across any peer namespace. **Never use in production** — bypasses all
/// authorization scoping.
///
/// R-5 (CROSS-IMPL-ACME-RUST): resource patterns use the
/// cross-namespace peer-wildcard form `/*/*` rather than bare `*` so
/// the grant covers paths under any peer namespace within the local
/// tree. The bare `*` resource canonicalizes to `/{local_peer_id}/*`
/// per `canonicalize`, which would reject writes to `/{X}/...` where
/// X is e.g. an ephemeral peer's signature-path namespace per V7 §6.5
/// invariant-pointer semantics. The peer-scope stays `*` (any local-side
/// `target_peer` value satisfies via `IdScope`).
pub fn debug_open_grants() -> Vec<GrantEntry> {
    use std::collections::BTreeMap;

    // Query-specific grant with content_store access + wildcard type_scope
    let mut type_scope = Vec::new();
    type_scope.push((
        ciborium::Value::Text("include".into()),
        ciborium::Value::Array(vec![ciborium::Value::Text("*".into())]),
    ));
    let mut constraints = BTreeMap::new();
    constraints.insert(
        "type_scope".to_string(),
        ciborium::Value::Map(type_scope),
    );
    let mut allowances = BTreeMap::new();
    allowances.insert(
        "scope".to_string(),
        ciborium::Value::Text("content_store".into()),
    );

    vec![
        // Query grant with content_store scope + wildcard type_scope
        GrantEntry {
            handlers: PathScope::new(vec!["system/query".into()]),
            resources: PathScope::new(vec!["/*/*".into()]),
            operations: IdScope::new(vec!["find".into(), "count".into()]),
            peers: None,
            constraints: Some(constraints),
            allowances: Some(allowances),
        },
        // General wildcard grant — resources are cross-namespace.
        GrantEntry {
            handlers: PathScope::new(vec!["*".into()]),
            resources: PathScope::new(vec!["/*/*".into()]),
            operations: IdScope::new(vec!["*".into()]),
            peers: Some(IdScope::new(vec!["*".into()])),
            constraints: None,
            allowances: None,
        },
    ]
}

/// Tree-binding storage path for a multi-sig root capability
/// (PROPOSAL-MULTISIG-CORE-PRIMITIVE M12).
///
/// Multi-sig root caps are stored at
/// `system/capability/grants/multi-sig-root/{cap_hash}`. `is_revoked` checks
/// the tree binding here; removing it revokes the cap.
///
/// `cap_hash` is rendered in the protocol's display form (`ecfv1-sha256:…`,
/// V7 §1.2). The path is bare (peer-relative); callers qualify with the
/// peer ID before tree access (peer-qualified paths convention).
pub fn capability_path_for_multisig_root(cap_hash: &Hash) -> String {
    format!("system/capability/grants/multi-sig-root/{}", cap_hash)
}

/// Principal-level owner-authority scope for a peer over its own namespace
/// `/{peer_id}/*` (F27 §6.9a peer-authority-bootstrap).
///
/// All handlers, all operations, all peers — resources scoped to the peer's
/// own namespace. This is the **principal-level** owner capability the
/// key-holder receives when authenticating as the peer's own identity over
/// the wire. It is distinct from the **handler-level** per-handler
/// self-grants ([`wildcard_handler_grant`] / `internal_scope`) that cover
/// peer-internal dispatch (§6.9a.4 coexistence — both are seeded at
/// peer-init; neither subsumes the other).
pub fn owner_self_grant(peer_id: &str) -> Vec<GrantEntry> {
    vec![GrantEntry {
        handlers: PathScope::all(),
        resources: PathScope::new(vec![format!("/{}/*", peer_id)]),
        operations: IdScope::all(),
        peers: Some(IdScope::all()),
        constraints: None,
        allowances: None,
    }]
}

/// Wildcard handler grant scope: all handlers, all resources, all operations, all peers.
///
/// Default scope for handlers that do not declare `internal_scope` (§6.9).
pub fn wildcard_handler_grant() -> Vec<GrantEntry> {
    vec![GrantEntry {
        handlers: PathScope::all(),
        resources: PathScope::all(),
        operations: IdScope::all(),
        peers: Some(IdScope::all()),
        constraints: None,
        allowances: None,
    }]
}

/// Resource target from an EXECUTE message (§3.2).
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceTarget {
    pub targets: Vec<String>,
    pub exclude: Vec<String>,
}

/// Multi-signature granter (PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.2 / M2).
///
/// `signers` are identity hashes (content hashes of `system/peer` entities,
/// V7 §1.5). `threshold` is K. The validity constraint is K ∈ [2, N], N ≥ 2,
/// no duplicate signers (M3); enforced at chain-walk entry by `validate`.
///
/// Encoded on the wire as a CBOR map with `signers` (array of bstr) and
/// `threshold` (uint). Distinguished from a single-sig granter (CBOR bstr) by
/// CBOR major type — no tag is emitted (M8).
#[derive(Debug, Clone, PartialEq)]
pub struct MultiGranter {
    pub signers: Vec<Hash>,
    pub threshold: u64,
}

impl MultiGranter {
    /// Validate M3 constraints. Called at MUST-level chain-walk entry.
    ///
    /// - N (signers count) ≥ 2 (use single-sig form for N=1)
    /// - K (threshold) ∈ [2, N] (K=0 invalid, K=1 invalid, K>N invalid)
    /// - No duplicate signers
    pub fn validate(&self) -> Result<(), CapabilityError> {
        let n = self.signers.len();
        if n < 2 {
            return Err(CapabilityError::Invalid(format!(
                "multi-granter must have N ≥ 2 signers, got {}",
                n
            )));
        }
        if self.threshold < 2 {
            return Err(CapabilityError::Invalid(format!(
                "multi-granter threshold K must be ≥ 2, got {}",
                self.threshold
            )));
        }
        if self.threshold > n as u64 {
            return Err(CapabilityError::Invalid(format!(
                "multi-granter threshold K ({}) exceeds N ({})",
                self.threshold, n
            )));
        }
        // Duplicate detection — small N (recommended ≤ 32, M9), O(n²) is fine.
        for i in 0..self.signers.len() {
            for j in (i + 1)..self.signers.len() {
                if self.signers[i] == self.signers[j] {
                    return Err(CapabilityError::Invalid(
                        "multi-granter contains duplicate signers".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Polymorphic granter (PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.1 / M1).
///
/// Either a single identity hash (single-sig, identical to today's behavior)
/// or a multi-sig granter (K-of-N). Multi-sig is restricted to root caps
/// (`parent: None`) by validity constraint M3.
#[derive(Debug, Clone, PartialEq)]
pub enum Granter {
    Single(Hash),
    Multi(MultiGranter),
}

impl Granter {
    /// Construct a single-sig granter from a hash.
    pub fn single(hash: Hash) -> Self {
        Granter::Single(hash)
    }

    /// Construct a multi-sig granter from a `MultiGranter` value.
    pub fn multi(multi: MultiGranter) -> Self {
        Granter::Multi(multi)
    }

    /// If single-sig, return the granter hash; otherwise None.
    pub fn as_single(&self) -> Option<&Hash> {
        match self {
            Granter::Single(h) => Some(h),
            Granter::Multi(_) => None,
        }
    }

    /// If multi-sig, return the multi-granter value; otherwise None.
    pub fn as_multi(&self) -> Option<&MultiGranter> {
        match self {
            Granter::Multi(m) => Some(m),
            Granter::Single(_) => None,
        }
    }

    pub fn is_multi(&self) -> bool {
        matches!(self, Granter::Multi(_))
    }
}

impl From<Hash> for Granter {
    fn from(h: Hash) -> Self {
        Granter::Single(h)
    }
}

/// Capability token data (§3.6).
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityToken {
    pub grants: Vec<GrantEntry>,
    /// Polymorphic granter — single-sig (`Granter::Single`) or multi-sig
    /// (`Granter::Multi`) per PROPOSAL-MULTISIG-CORE-PRIMITIVE M1.
    /// Multi-sig requires `parent: None` (M3).
    pub granter: Granter,
    pub grantee: Hash,
    pub parent: Option<Hash>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub not_before: Option<u64>,
    pub delegation_caveats: Option<DelegationCaveats>,
}

/// Delegation caveats — flat struct, NOT an array (§5.7).
#[derive(Debug, Clone, PartialEq)]
pub struct DelegationCaveats {
    pub no_delegation: Option<bool>,
    pub max_delegation_depth: Option<u64>,
    pub max_delegation_ttl: Option<u64>,
}

// ---------------------------------------------------------------------------
// Pattern matching (§5.4)
// ---------------------------------------------------------------------------

/// Canonicalize a path or pattern to absolute form.
///
/// Returns `None` for malformed patterns, which callers MUST treat as a
/// deny (V7 §1.11 fail-closed). A malformed pattern presented in a
/// capability must yield a clean DENY response, never a panic or dropped
/// connection.
///
/// Rules:
/// - `starts_with("/")` → pass through (already absolute)
/// - `"*"` → `"/{local_peer_id}/*"` (peer-relative wildcard)
/// - `"./..."` / `"../..."` → `None` (reserved)
/// - `"*/..."` → `None` (ambiguous — use `/*/...`)
/// - bare path → `"/{local_peer_id}/{path}"`
pub fn canonicalize(path: &str, local_peer_id: &str) -> Option<String> {
    // Reject reserved directory-relative prefixes
    if path.starts_with("./") || path.starts_with("../") {
        return None;
    }
    // Reject ambiguous bare */rest — must use /*/rest
    if path.starts_with("*/") {
        return None;
    }
    // Already absolute — pass through
    if path.starts_with('/') {
        return Some(path.to_string());
    }
    // Bare wildcard → local peer all paths
    if path == "*" {
        return Some(format!("/{}/*", local_peer_id));
    }
    // Bare path — prepend / + local peer
    Some(format!("/{}/{}", local_peer_id, path))
}

/// Check if a concrete path matches a pattern (§5.4).
///
/// Both `path` and `pattern` should already be canonicalized (absolute).
///
/// Pattern types:
/// - `*` — matches everything (recursive case from `/*/*` decomposition)
/// - `prefix/*` — subtree match (path starts with prefix)
/// - `/*/rest` — peer wildcard (any peer, match rest)
/// - anything else — exact match
pub fn matches_pattern(path: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Peer wildcard: /*/rest — match any peer's subtree
    if let Some(remainder) = pattern.strip_prefix("/*/") {
        // path is /{peer_id}/rest — extract rest after peer segment
        if let Some(after_slash) = path.strip_prefix('/') {
            if let Some(slash) = after_slash.find('/') {
                let path_rest = &after_slash[slash + 1..];
                // Recurse: both sides are now bare sub-paths
                return matches_pattern(path_rest, remainder);
            }
        }
        return false;
    }

    // Subtree prefix: prefix/*
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path.starts_with(prefix) && path.len() > prefix.len() && path.as_bytes()[prefix.len()] == b'/';
    }

    // Exact match
    path == pattern
}

/// Check if a value matches a scope (include/exclude) (§5.4).
///
/// The value must match at least one include pattern and must not
/// match any exclude pattern.
pub fn matches_scope(value: &str, include: &[String], exclude: &[String], local_peer_id: &str) -> bool {
    // Fail-closed (§1.11): a malformed value denies rather than panics.
    let cv = match canonicalize(value, local_peer_id) {
        Some(v) => v,
        None => return false,
    };

    // A malformed include can never grant — it simply doesn't match.
    let matched = include
        .iter()
        .any(|pattern| canonicalize(pattern, local_peer_id).is_some_and(|cp| matches_pattern(&cv, &cp)));

    if !matched {
        return false;
    }

    // A malformed exclude fails closed: treat it as if it matched (deny),
    // never as a silent no-op that would under-exclude.
    let excluded = exclude
        .iter()
        .any(|pattern| canonicalize(pattern, local_peer_id).is_none_or(|cp| matches_pattern(&cv, &cp)));

    !excluded
}

/// Check if a path/pattern is covered by a set of patterns.
fn is_covered_by(path: &str, pattern_set: &[String], local_peer_id: &str) -> bool {
    // A malformed pattern cannot cover anything (fail-closed).
    pattern_set
        .iter()
        .any(|p| canonicalize(p, local_peer_id).is_some_and(|cp| matches_pattern(path, &cp)))
}

/// Check if a string contains a wildcard.
fn is_pattern(path: &str) -> bool {
    path.contains('*')
}

/// Strip trailing wildcard for overlap checking.
fn strip_wildcard(pattern: &str) -> &str {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        prefix
    } else if pattern == "*" {
        ""
    } else {
        pattern
    }
}

/// Check if two patterns could match any common concrete path.
fn patterns_overlap(a: &str, b: &str) -> bool {
    let pa = strip_wildcard(a);
    let pb = strip_wildcard(b);
    pa.starts_with(pb) || pb.starts_with(pa)
}

// ---------------------------------------------------------------------------
// Permission checking (§5.4)
// ---------------------------------------------------------------------------

/// Check whether a capability authorizes an operation (§5.4).
///
/// This is the Level 1 "dispatch scope" check, called after handler resolution.
/// All four dimensions must match within the same grant entry.
pub fn check_permission(
    operation: &str,
    handler_pattern: &str,
    target_peer: &str,
    resource_target: Option<&ResourceTarget>,
    capability: &CapabilityToken,
    local_peer_id: &str,
) -> bool {
    for grant in &capability.grants {
        // Operations
        if !matches_scope(
            operation,
            &grant.operations.include,
            &grant.operations.exclude,
            local_peer_id,
        ) {
            continue;
        }

        // Handlers
        if !matches_scope(
            handler_pattern,
            &grant.handlers.include,
            &grant.handlers.exclude,
            local_peer_id,
        ) {
            continue;
        }

        // Peers
        let default_peers = IdScope::new(vec![local_peer_id.into()]);
        let peers = grant.peers.as_ref().unwrap_or(&default_peers);
        if !matches_scope(
            target_peer,
            &peers.include,
            &peers.exclude,
            local_peer_id,
        ) {
            continue;
        }

        // Resources — only checked when resource is present.
        // This entry point keeps the self-issued (granter == local) frame:
        // the dispatch boundary that needs granter-aware canonicalization
        // (PR-8) goes through `check_permission_with_grant`.
        if let Some(rt) = resource_target {
            if !check_resource_scope(rt, &grant.resources, local_peer_id, local_peer_id) {
                continue;
            }
        }

        return true;
    }
    false
}

/// Check permission and return the matching grant entry (§5.4).
///
/// Same logic as `check_permission`, but returns a clone of the first
/// matching grant entry. This is needed by handlers that inspect the
/// grant's `constraints` field (e.g., the query handler).
///
/// `granter_peer_id` is the namespace frame for the cap's peer-relative
/// resource patterns (V7 §5.5 / PR-8) — resolve it from the cap's `granter`
/// via [`resolve_granter_peer_id`]. This is the dispatch-time authorization
/// boundary; pass the real granter so a foreign-granted bare-`*` cap cannot
/// reach the verifier's namespace.
pub fn check_permission_with_grant(
    operation: &str,
    handler_pattern: &str,
    target_peer: &str,
    resource_target: Option<&ResourceTarget>,
    capability: &CapabilityToken,
    local_peer_id: &str,
    granter_peer_id: &str,
) -> Option<GrantEntry> {
    for grant in &capability.grants {
        if !matches_scope(
            operation,
            &grant.operations.include,
            &grant.operations.exclude,
            local_peer_id,
        ) {
            continue;
        }
        if !matches_scope(
            handler_pattern,
            &grant.handlers.include,
            &grant.handlers.exclude,
            local_peer_id,
        ) {
            continue;
        }
        let default_peers = IdScope::new(vec![local_peer_id.into()]);
        let peers = grant.peers.as_ref().unwrap_or(&default_peers);
        if !matches_scope(
            target_peer,
            &peers.include,
            &peers.exclude,
            local_peer_id,
        ) {
            continue;
        }
        if let Some(rt) = resource_target {
            if !check_resource_scope(rt, &grant.resources, local_peer_id, granter_peer_id) {
                continue;
            }
        }
        return Some(grant.clone());
    }
    None
}

/// Resolve the peer_id whose namespace a capability's peer-relative resource
/// patterns canonicalize against (V7 §5.5 / PR-8).
///
/// Single-sig granters resolve to the granter identity's derived peer_id;
/// multi-sig granters fall back to the local peer (M3 root-only — multi-sig
/// caps are locally rooted, §5.5 root-trust). For a self-issued cap (granter
/// == local peer) the result equals `local_peer_id`.
///
/// `lookup` resolves a granter hash to its `system/peer` entity — pass a
/// closure over the envelope's `included` map (or content store). Returns
/// `None` when a single-sig granter cannot be resolved to a present
/// `system/peer` entity; callers MUST treat `None` as fail-closed (deny, §1.11).
pub fn resolve_granter_peer_id<'a>(
    granter: &Granter,
    local_peer_id: &str,
    lookup: impl FnOnce(&Hash) -> Option<&'a entity_entity::Entity>,
) -> Option<String> {
    let granter_hash = match granter.as_single() {
        Some(h) => h,
        None => return Some(local_peer_id.to_string()), // multi-sig → local
    };
    let granter_entity = lookup(granter_hash)?;
    if granter_entity.entity_type != entity_types::TYPE_PEER {
        return None;
    }
    entity_types::PeerData::from_entity(granter_entity)
        .ok()?
        .canonical_peer_id()
}

/// Check resource scope — caller's requested targets must fit within grant scope (§5.2).
///
/// Two canonicalization frames (V7 §5.5 / PR-8): the **request target** and the
/// caller's own exclude canonicalize against `local_peer_id` (request-path
/// semantics, §5.4); the **grant's** include/exclude patterns canonicalize
/// against `granter_peer_id` — a bare `*` in a cap resource means
/// `/{granter_peer_id}/*` (the granter's namespace), never the verifier's. For
/// a self-issued cap the two frames coincide (pass `local_peer_id` for both).
pub fn check_resource_scope(
    resource_target: &ResourceTarget,
    grant_resources: &PathScope,
    local_peer_id: &str,
    granter_peer_id: &str,
) -> bool {
    let caller_exclude = &resource_target.exclude;
    let grant_include = &grant_resources.include;
    let grant_exclude = &grant_resources.exclude;

    for target in &resource_target.targets {
        // Fail-closed: a malformed requested target denies the whole check.
        let ct = match canonicalize(target, local_peer_id) {
            Some(v) => v,
            None => return false,
        };

        // Skip targets fully covered by caller's own exclude (request frame)
        if is_covered_by(&ct, caller_exclude, local_peer_id) {
            continue;
        }

        // Target must be covered by grant include (granter frame per PR-8)
        if !is_covered_by(&ct, grant_include, granter_peer_id) {
            return false;
        }

        if is_pattern(&ct) {
            // Pattern target: grant excludes must be covered by caller excludes
            for ge in grant_exclude {
                // A malformed grant exclude can't be reasoned about → deny.
                let cge = match canonicalize(ge, granter_peer_id) {
                    Some(v) => v,
                    None => return false,
                };
                if !patterns_overlap(&ct, &cge) {
                    continue;
                }
                if !is_covered_by(&cge, caller_exclude, local_peer_id) {
                    return false;
                }
            }
        } else {
            // Concrete target: must not be in grant exclude (granter frame)
            for ge in grant_exclude {
                // A malformed grant exclude can't be reasoned about → deny.
                let cge = match canonicalize(ge, granter_peer_id) {
                    Some(v) => v,
                    None => return false,
                };
                if matches_pattern(&ct, &cge) {
                    return false;
                }
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Attenuation (§5.6)
// ---------------------------------------------------------------------------

/// Check that a child capability is a valid attenuation of its parent.
///
/// The child can only restrict, never amplify — every child grant must be
/// covered by some parent grant, and expiration cannot exceed parent's.
///
/// **Self-issued frame:** both caps' peer-relative resource patterns
/// canonicalize against `local_peer_id`. Correct when granter == local peer at
/// every link (the dominant self-issued path: capability/role handlers minting
/// from the caller's own cap). For a delegation **chain** whose links have
/// *different* granters, use [`is_attenuated_framed`] — V7 §5.5a requires each
/// link's resources to canonicalize against its OWN granter's namespace.
pub fn is_attenuated(
    child: &CapabilityToken,
    parent: &CapabilityToken,
    local_peer_id: &str,
) -> bool {
    is_attenuated_inner(child, parent, local_peer_id, local_peer_id, local_peer_id)
}

/// Per-link granter-frame attenuation check (V7 §5.5a / §PR-8 — the chain-walk
/// surface, distinct from the dispatch boundary).
///
/// Identical to [`is_attenuated`] except each cap's **resource** patterns
/// canonicalize against ITS OWN granter's peer_id — `child_granter_peer_id`
/// for the child cap, `parent_granter_peer_id` for the parent. Per V7 §5.5 a
/// bare `*` means `/{granter_peer_id}/*` (the granter's own namespace), so a
/// foreign-granted bare `*` in a parent link no longer silently covers the
/// verifier's namespace — the V1' authority-escalation the cohort confirmed.
/// Handlers, operations, and peers carry no peer-id namespace semantics and
/// stay on `local_peer_id`. `verify_capability_chain` derives both granter
/// peer_ids from the chain's included identities and calls this; self-issued
/// callers use [`is_attenuated`] (granter == local at every link).
pub fn is_attenuated_framed(
    child: &CapabilityToken,
    parent: &CapabilityToken,
    child_granter_peer_id: &str,
    parent_granter_peer_id: &str,
    local_peer_id: &str,
) -> bool {
    is_attenuated_inner(
        child,
        parent,
        child_granter_peer_id,
        parent_granter_peer_id,
        local_peer_id,
    )
}

fn is_attenuated_inner(
    child: &CapabilityToken,
    parent: &CapabilityToken,
    child_granter_peer_id: &str,
    parent_granter_peer_id: &str,
    local_peer_id: &str,
) -> bool {
    // Every child grant must be covered by some parent grant
    for child_grant in &child.grants {
        if !grant_covered_by(
            child_grant,
            &parent.grants,
            child_granter_peer_id,
            parent_granter_peer_id,
            local_peer_id,
        ) {
            return false;
        }
    }

    // Child expiration must not exceed parent's
    if let Some(parent_exp) = parent.expires_at {
        match child.expires_at {
            None => return false, // child infinite, parent finite
            Some(child_exp) if child_exp > parent_exp => return false,
            _ => {}
        }
    }

    true
}

/// Check if a child grant is covered by any parent grant.
fn grant_covered_by(
    child_grant: &GrantEntry,
    parent_grants: &[GrantEntry],
    child_granter_peer_id: &str,
    parent_granter_peer_id: &str,
    local_peer_id: &str,
) -> bool {
    parent_grants.iter().any(|pg| {
        grant_subset(
            child_grant,
            pg,
            child_granter_peer_id,
            parent_granter_peer_id,
            local_peer_id,
        )
    })
}

/// Check if a child grant is a subset of a parent grant (all four dimensions).
///
/// Per V7 §5.5a / §PR-8, only the **resource** dimension is granter-frame-
/// relative: child resources canonicalize against `child_granter_peer_id`,
/// parent resources against `parent_granter_peer_id`. Handlers, operations,
/// and peers have no peer-id namespace semantics and stay on `local_peer_id`
/// for both sides (existing behavior).
fn grant_subset(
    child: &GrantEntry,
    parent: &GrantEntry,
    child_granter_peer_id: &str,
    parent_granter_peer_id: &str,
    local_peer_id: &str,
) -> bool {
    // Handlers: no §PR-8 frame — both sides canonicalize under local_peer_id.
    if !scope_subset_path(&child.handlers, &parent.handlers, local_peer_id, local_peer_id) {
        return false;
    }
    if !scope_subset_id(&child.operations, &parent.operations, local_peer_id) {
        return false;
    }
    // Resources: §PR-8 per-link granter frame (child vs parent granter).
    if !scope_subset_path(
        &child.resources,
        &parent.resources,
        child_granter_peer_id,
        parent_granter_peer_id,
    ) {
        return false;
    }
    let default_peers = IdScope::new(vec![local_peer_id.into()]);
    let child_peers = child.peers.as_ref().unwrap_or(&default_peers);
    let parent_peers = parent.peers.as_ref().unwrap_or(&default_peers);
    if !scope_subset_id(child_peers, parent_peers, local_peer_id) {
        return false;
    }

    // Constraint attenuation (§5.6): child MUST retain all parent constraint keys
    // with byte-identical values. Child MAY add new constraint keys (narrows).
    let empty_map = std::collections::BTreeMap::new();
    let parent_constraints = parent.constraints.as_ref().unwrap_or(&empty_map);
    let child_constraints = child.constraints.as_ref().unwrap_or(&empty_map);
    for (key, parent_val) in parent_constraints {
        match child_constraints.get(key) {
            None => return false, // Key dropped — escalation
            Some(child_val) if !cbor_bytes_equal(parent_val, child_val) => return false, // Value changed
            _ => {} // Key present, value identical
        }
    }

    // Allowance attenuation (§5.6): child MUST NOT add keys parent doesn't have.
    // Child MAY remove allowance keys (narrows).
    let parent_allowances = parent.allowances.as_ref().unwrap_or(&empty_map);
    let child_allowances = child.allowances.as_ref().unwrap_or(&empty_map);
    for (key, child_val) in child_allowances {
        match parent_allowances.get(key) {
            None => return false, // Key added — escalation
            Some(parent_val) if !cbor_bytes_equal(parent_val, child_val) => return false, // Value changed
            _ => {} // Key present, value identical
        }
    }

    true
}

/// Compare two ciborium::Values by their canonical CBOR encoding.
fn cbor_bytes_equal(a: &ciborium::Value, b: &ciborium::Value) -> bool {
    let mut buf_a = Vec::new();
    let mut buf_b = Vec::new();
    if ciborium::into_writer(a, &mut buf_a).is_err() {
        return false;
    }
    if ciborium::into_writer(b, &mut buf_b).is_err() {
        return false;
    }
    buf_a == buf_b
}

/// Check if child PathScope is a subset of parent PathScope (§5.6).
///
/// Each side canonicalizes its peer-relative patterns against its OWN frame
/// (V7 §5.5a / §PR-8): child against `child_canon_peer_id`, parent against
/// `parent_canon_peer_id`. For dimensions where §PR-8 does not apply (handlers),
/// callers pass the same `local_peer_id` for both — one frame, behavior
/// unchanged.
fn scope_subset_path(
    child: &PathScope,
    parent: &PathScope,
    child_canon_peer_id: &str,
    parent_canon_peer_id: &str,
) -> bool {
    // Every child include must be covered by some parent include
    for ci in &child.include {
        let cc = match canonicalize(ci, child_canon_peer_id) {
            Some(v) => v,
            None => return false,
        };
        if !parent.include.iter().any(|pi| {
            canonicalize(pi, parent_canon_peer_id).is_some_and(|cp| matches_pattern(&cc, &cp))
        }) {
            return false;
        }
    }

    // Child must inherit ALL parent excludes
    for pe in &parent.exclude {
        let cp = match canonicalize(pe, parent_canon_peer_id) {
            Some(v) => v,
            None => return false,
        };
        let child_has = child.exclude.iter().any(|ce| {
            canonicalize(ce, child_canon_peer_id).is_some_and(|cc| matches_pattern(&cp, &cc))
        });
        if !child_has {
            return false;
        }
    }

    true
}

/// Check if child IdScope is a subset of parent IdScope.
fn scope_subset_id(child: &IdScope, parent: &IdScope, local_peer_id: &str) -> bool {
    for ci in &child.include {
        let cc = match canonicalize(ci, local_peer_id) {
            Some(v) => v,
            None => return false,
        };
        if !parent
            .include
            .iter()
            .any(|pi| canonicalize(pi, local_peer_id).is_some_and(|cp| matches_pattern(&cc, &cp)))
        {
            return false;
        }
    }

    for pe in &parent.exclude {
        let cp = match canonicalize(pe, local_peer_id) {
            Some(v) => v,
            None => return false,
        };
        let child_has = child
            .exclude
            .iter()
            .any(|ce| canonicalize(ce, local_peer_id).is_some_and(|cc| matches_pattern(&cp, &cc)));
        if !child_has {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Delegation caveats (§5.7)
// ---------------------------------------------------------------------------

/// Check delegation caveats from parent against child capability.
pub fn check_delegation_caveats(
    parent: &CapabilityToken,
    child: &CapabilityToken,
    depth: u64,
) -> bool {
    let caveats = match &parent.delegation_caveats {
        None => return true,
        Some(c) => c,
    };

    if caveats.no_delegation == Some(true) {
        return false;
    }

    if let Some(max_depth) = caveats.max_delegation_depth {
        if depth >= max_depth {
            return false;
        }
    }

    if let Some(max_ttl) = caveats.max_delegation_ttl {
        match child.expires_at {
            None => return false, // infinite lifetime exceeds any finite limit
            Some(exp) => {
                let child_ttl = exp.saturating_sub(child.created_at);
                if child_ttl > max_ttl {
                    return false;
                }
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// CBOR encode/decode for CapabilityToken
// ---------------------------------------------------------------------------

impl CapabilityToken {
    /// Validate well-formedness of the cap (SEC-18 / M3 / V7 v7.39 PR-3).
    ///
    /// Defense-in-depth check intended to be called by mint-time call sites
    /// (role assign/delegate, custom cap-issuance handlers). Mirrors Go's
    /// `CapabilityTokenData.ValidateStructure`. Returns:
    /// - `Invalid` for the M3 multi-sig parent constraint
    /// - `Invalid` (with an `unresolvable_grantee` marker in the message)
    ///   for a zero-hash grantee — never resolves to a `system/peer` entity,
    ///   so the cap would fail chain-walk under PR-3 anyway.
    ///
    /// Chain-walk in `core/protocol/verify.rs::verify_capability_chain` is
    /// the load-bearing enforcement; this method just lets issuers fail
    /// fast at mint time instead of leaving a dud cap bound in the tree.
    pub fn validate_structure(&self) -> Result<(), CapabilityError> {
        if let Granter::Multi(multi) = &self.granter {
            if self.parent.is_some() {
                return Err(CapabilityError::Invalid(
                    "multi-sig capability MUST have parent: null (M3)".into(),
                ));
            }
            multi.validate()?;
        }
        if self.grantee.is_zero() {
            return Err(CapabilityError::Invalid(
                "unresolvable_grantee: capability grantee MUST be a non-zero \
                 hash (SEC-18 / V7 v7.39 PR-3)"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Encode to ECF bytes suitable for creating an entity.
    pub fn to_ecf(&self) -> Vec<u8> {
        use entity_ecf::{integer, text, Value};

        let mut entries = Vec::new();

        // created_at
        entries.push((text("created_at"), integer(self.created_at as i64)));

        // delegation_caveats
        if let Some(ref dc) = self.delegation_caveats {
            entries.push((text("delegation_caveats"), dc.to_value()));
        }

        // expires_at
        if let Some(exp) = self.expires_at {
            entries.push((text("expires_at"), integer(exp as i64)));
        }

        // grantee
        entries.push((
            text("grantee"),
            Value::Bytes(self.grantee.to_bytes().to_vec()),
        ));

        // granter — polymorphic per M1/M8: bstr for single-sig, map for multi-sig
        entries.push((text("granter"), encode_granter(&self.granter)));

        // grants
        let grants: Vec<Value> = self.grants.iter().map(|g| g.to_value()).collect();
        entries.push((text("grants"), Value::Array(grants)));

        // not_before
        if let Some(nb) = self.not_before {
            entries.push((text("not_before"), integer(nb as i64)));
        }

        // parent
        if let Some(ref p) = self.parent {
            entries.push((text("parent"), Value::Bytes(p.to_bytes().to_vec())));
        }

        entity_ecf::to_ecf(&Value::Map(entries))
    }

    /// Create an entity from this capability token under the process home
    /// `content_hash_format` ([`entity_hash::default_hash_format`] — V7 §1.2).
    /// Connection caps minted under a negotiated active format (§4.5a) use
    /// [`CapabilityToken::to_entity_with_format`] instead.
    pub fn to_entity(&self) -> Result<entity_entity::Entity, CapabilityError> {
        self.to_entity_with_format(entity_hash::default_hash_format())
    }

    /// Create an entity from this capability token under an explicit
    /// `content_hash_format` (V7 §4.5a — mint connection caps under the
    /// negotiated active format). A cap chain has a self-consistent format
    /// (§5.5 freeze), so every link a peer mints for a connection uses the
    /// connection's active format.
    pub fn to_entity_with_format(
        &self,
        format_code: u8,
    ) -> Result<entity_entity::Entity, CapabilityError> {
        let data = self.to_ecf();
        entity_entity::Entity::new_with_format(entity_types::TYPE_CAP_TOKEN, data, format_code)
            .map_err(|e| CapabilityError::EntityError(e.to_string()))
    }

    /// Decode a CapabilityToken from an entity.
    pub fn from_entity(entity: &entity_entity::Entity) -> Result<Self, CapabilityError> {
        if entity.entity_type != entity_types::TYPE_CAP_TOKEN {
            return Err(CapabilityError::Invalid(format!(
                "expected {}, got {}",
                entity_types::TYPE_CAP_TOKEN,
                entity.entity_type
            )));
        }

        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| CapabilityError::Invalid(e.to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| CapabilityError::Invalid("capability data must be a map".into()))?;

        let mut grants = None;
        let mut granter = None;
        let mut grantee = None;
        let mut parent = None;
        let mut created_at = None;
        let mut expires_at = None;
        let mut not_before = None;
        let mut delegation_caveats = None;

        for (k, v) in map {
            match k.as_text() {
                Some("grants") => {
                    let arr = v.as_array().ok_or_else(|| {
                        CapabilityError::Invalid("grants must be an array".into())
                    })?;
                    let mut entries = Vec::new();
                    for item in arr {
                        entries.push(decode_grant_entry(item)?);
                    }
                    grants = Some(entries);
                }
                Some("granter") => {
                    granter = Some(decode_granter(v)?);
                }
                Some("grantee") => {
                    if let Some(b) = v.as_bytes() {
                        grantee = Some(
                            Hash::from_bytes(b)
                                .map_err(|e| CapabilityError::Invalid(e.to_string()))?,
                        );
                    }
                }
                Some("parent") => {
                    if let Some(b) = v.as_bytes() {
                        parent = Some(
                            Hash::from_bytes(b)
                                .map_err(|e| CapabilityError::Invalid(e.to_string()))?,
                        );
                    }
                }
                Some("created_at") => {
                    created_at = v.as_integer().and_then(|i| u64::try_from(i).ok());
                }
                Some("expires_at") => {
                    expires_at = v.as_integer().and_then(|i| u64::try_from(i).ok());
                }
                Some("not_before") => {
                    not_before = v.as_integer().and_then(|i| u64::try_from(i).ok());
                }
                Some("delegation_caveats") => {
                    delegation_caveats = Some(decode_delegation_caveats(v)?);
                }
                _ => {}
            }
        }

        Ok(CapabilityToken {
            grants: grants
                .ok_or_else(|| CapabilityError::Invalid("missing grants".into()))?,
            granter: granter
                .ok_or_else(|| CapabilityError::Invalid("missing granter".into()))?,
            grantee: grantee
                .ok_or_else(|| CapabilityError::Invalid("missing grantee".into()))?,
            parent,
            created_at: created_at
                .ok_or_else(|| CapabilityError::Invalid("missing created_at".into()))?,
            expires_at,
            not_before,
            delegation_caveats,
        })
    }
}

impl GrantEntry {
    fn to_value(&self) -> entity_ecf::Value {
        encode_grant_entry(self)
    }
}

/// Encode a grant entry to ECF CBOR. Public so consumer extensions
/// (identity peer-config, role) can serialize grants without a full
/// CapabilityToken round-trip.
pub fn encode_grant_entry(g: &GrantEntry) -> entity_ecf::Value {
    use entity_ecf::{text, Value};
    let mut entries = Vec::new();
    if let Some(ref allowances) = g.allowances {
        entries.push((text("allowances"), string_map_to_ecf(allowances)));
    }
    if let Some(ref constraints) = g.constraints {
        entries.push((text("constraints"), string_map_to_ecf(constraints)));
    }
    entries.push((text("handlers"), scope_to_value_path(&g.handlers)));
    entries.push((text("operations"), scope_to_value_id(&g.operations)));
    if let Some(ref peers) = g.peers {
        entries.push((text("peers"), scope_to_value_id(peers)));
    }
    entries.push((text("resources"), scope_to_value_path(&g.resources)));
    Value::Map(entries)
}

/// Convert a BTreeMap<String, ciborium::Value> to entity_ecf::Value for encoding.
fn string_map_to_ecf(map: &std::collections::BTreeMap<String, ciborium::Value>) -> entity_ecf::Value {
    use entity_ecf::{text, Value};
    Value::Map(
        map.iter()
            .map(|(k, v)| (text(k), ciborium_to_ecf(v)))
            .collect(),
    )
}

/// Convert a ciborium::Value to entity_ecf::Value for encoding in grant entries.
fn ciborium_to_ecf(val: &ciborium::Value) -> entity_ecf::Value {
    use entity_ecf::Value;
    match val {
        ciborium::Value::Null => Value::Null,
        ciborium::Value::Bool(b) => Value::Bool(*b),
        ciborium::Value::Integer(i) => {
            let n: i128 = (*i).into();
            entity_ecf::integer(n as i64)
        }
        ciborium::Value::Text(s) => Value::Text(s.clone()),
        ciborium::Value::Bytes(b) => Value::Bytes(b.clone()),
        ciborium::Value::Array(arr) => {
            Value::Array(arr.iter().map(ciborium_to_ecf).collect())
        }
        ciborium::Value::Map(map) => {
            Value::Map(
                map.iter()
                    .map(|(k, v)| (ciborium_to_ecf(k), ciborium_to_ecf(v)))
                    .collect(),
            )
        }
        ciborium::Value::Float(f) => Value::Float(*f),
        _ => Value::Null,
    }
}

fn scope_to_value_path(scope: &PathScope) -> entity_ecf::Value {
    use entity_ecf::{text, Value};
    let mut entries = Vec::new();
    if !scope.exclude.is_empty() {
        let exc: Vec<Value> = scope.exclude.iter().map(text).collect();
        entries.push((text("exclude"), Value::Array(exc)));
    }
    let inc: Vec<Value> = scope.include.iter().map(text).collect();
    entries.push((text("include"), Value::Array(inc)));
    Value::Map(entries)
}

fn scope_to_value_id(scope: &IdScope) -> entity_ecf::Value {
    use entity_ecf::{text, Value};
    let mut entries = Vec::new();
    if !scope.exclude.is_empty() {
        let exc: Vec<Value> = scope.exclude.iter().map(text).collect();
        entries.push((text("exclude"), Value::Array(exc)));
    }
    let inc: Vec<Value> = scope.include.iter().map(text).collect();
    entries.push((text("include"), Value::Array(inc)));
    Value::Map(entries)
}

/// Encode a `Granter` to ECF Value (M8).
///
/// - `Granter::Single(hash)` → CBOR byte string (major type 2)
/// - `Granter::Multi(multi)` → CBOR map (major type 5) with `signers` and `threshold`
///
/// No CBOR tags are emitted (ENTITY-CBOR-ENCODING.md §11).
pub fn encode_granter(granter: &Granter) -> entity_ecf::Value {
    use entity_ecf::{integer, text, Value};
    match granter {
        Granter::Single(h) => Value::Bytes(h.to_bytes().to_vec()),
        Granter::Multi(m) => {
            let signers: Vec<Value> = m
                .signers
                .iter()
                .map(|h| Value::Bytes(h.to_bytes().to_vec()))
                .collect();
            // ECF key order: signers, threshold (alphabetical)
            Value::Map(vec![
                (text("signers"), Value::Array(signers)),
                (text("threshold"), integer(m.threshold as i64)),
            ])
        }
    }
}

/// Decode a `Granter` from a CBOR value (M8).
///
/// Branches on CBOR major type:
/// - byte string (`as_bytes`) → `Granter::Single`
/// - map (`as_map`) → `Granter::Multi`
/// - any other type (including tag-wrapped) → reject (M8 bans tags on data fields)
pub fn decode_granter(value: &ciborium::Value) -> Result<Granter, CapabilityError> {
    // Tag rejection (M8 / ENTITY-CBOR-ENCODING.md §11): test vector #18c.
    if matches!(value, ciborium::Value::Tag(_, _)) {
        return Err(CapabilityError::Invalid(
            "granter MUST NOT be CBOR-tagged (ENTITY-CBOR-ENCODING.md §11)".into(),
        ));
    }
    if let Some(b) = value.as_bytes() {
        let h = Hash::from_bytes(b).map_err(|e| CapabilityError::Invalid(e.to_string()))?;
        return Ok(Granter::Single(h));
    }
    if let Some(map) = value.as_map() {
        let mut signers: Option<Vec<Hash>> = None;
        let mut threshold: Option<u64> = None;
        for (k, v) in map {
            match k.as_text() {
                Some("signers") => {
                    let arr = v.as_array().ok_or_else(|| {
                        CapabilityError::Invalid(
                            "multi-granter signers must be an array".into(),
                        )
                    })?;
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        let bytes = item.as_bytes().ok_or_else(|| {
                            CapabilityError::Invalid(
                                "multi-granter signer entries must be byte strings".into(),
                            )
                        })?;
                        out.push(
                            Hash::from_bytes(bytes)
                                .map_err(|e| CapabilityError::Invalid(e.to_string()))?,
                        );
                    }
                    signers = Some(out);
                }
                Some("threshold") => {
                    threshold = v.as_integer().and_then(|i| u64::try_from(i).ok());
                }
                _ => {}
            }
        }
        let signers = signers
            .ok_or_else(|| CapabilityError::Invalid("multi-granter missing signers".into()))?;
        let threshold = threshold
            .ok_or_else(|| CapabilityError::Invalid("multi-granter missing threshold".into()))?;
        return Ok(Granter::Multi(MultiGranter { signers, threshold }));
    }
    Err(CapabilityError::Invalid(
        "granter must be a byte string (single-sig) or map (multi-sig)".into(),
    ))
}

/// Decode a single grant entry CBOR value into a GrantEntry struct.
/// Made public so handler-side code (e.g., the handlers handler installing a
/// derived grant from a manifest's `internal_scope` array) can decode without
/// going through full CapabilityToken::from_entity round-trips.
pub fn decode_grant_entry(value: &ciborium::Value) -> Result<GrantEntry, CapabilityError> {
    let map = value
        .as_map()
        .ok_or_else(|| CapabilityError::Invalid("grant entry must be a map".into()))?;

    let mut handlers = None;
    let mut resources = None;
    let mut operations = None;
    let mut peers = None;
    let mut constraints = None;
    let mut allowances = None;

    for (k, v) in map {
        match k.as_text() {
            Some("handlers") => handlers = Some(decode_path_scope(v)?),
            Some("resources") => resources = Some(decode_path_scope(v)?),
            Some("operations") => operations = Some(decode_id_scope(v)?),
            Some("peers") => peers = Some(decode_id_scope(v)?),
            Some("constraints") => constraints = Some(decode_string_keyed_map(v)),
            Some("allowances") => allowances = Some(decode_string_keyed_map(v)),
            _ => {}
        }
    }

    Ok(GrantEntry {
        handlers: handlers
            .ok_or_else(|| CapabilityError::Invalid("missing handlers in grant".into()))?,
        resources: resources
            .ok_or_else(|| CapabilityError::Invalid("missing resources in grant".into()))?,
        operations: operations
            .ok_or_else(|| CapabilityError::Invalid("missing operations in grant".into()))?,
        peers,
        constraints,
        allowances,
    })
}

/// Decode a CBOR map into a BTreeMap<String, ciborium::Value>.
/// Non-map values are treated as empty maps (defensive).
fn decode_string_keyed_map(value: &ciborium::Value) -> std::collections::BTreeMap<String, ciborium::Value> {
    let mut result = std::collections::BTreeMap::new();
    if let Some(entries) = value.as_map() {
        for (k, v) in entries {
            if let Some(key) = k.as_text() {
                result.insert(key.to_string(), v.clone());
            }
        }
    }
    result
}

/// Decode include/exclude string lists from a CBOR scope map.
fn decode_scope_lists(value: &ciborium::Value) -> Result<(Vec<String>, Vec<String>), CapabilityError> {
    let map = value
        .as_map()
        .ok_or_else(|| CapabilityError::Invalid("scope must be a map".into()))?;

    let mut include = Vec::new();
    let mut exclude = Vec::new();

    for (k, v) in map {
        let target = match k.as_text() {
            Some("include") => &mut include,
            Some("exclude") => &mut exclude,
            _ => continue,
        };
        if let Some(arr) = v.as_array() {
            for item in arr {
                if let Some(s) = item.as_text() {
                    target.push(s.to_string());
                }
            }
        }
    }

    Ok((include, exclude))
}

fn decode_path_scope(value: &ciborium::Value) -> Result<PathScope, CapabilityError> {
    let (include, exclude) = decode_scope_lists(value)?;
    Ok(PathScope { include, exclude })
}

fn decode_id_scope(value: &ciborium::Value) -> Result<IdScope, CapabilityError> {
    let (include, exclude) = decode_scope_lists(value)?;
    Ok(IdScope { include, exclude })
}

fn decode_delegation_caveats(
    value: &ciborium::Value,
) -> Result<DelegationCaveats, CapabilityError> {
    let map = value
        .as_map()
        .ok_or_else(|| CapabilityError::Invalid("delegation_caveats must be a map".into()))?;

    let mut no_delegation = None;
    let mut max_delegation_depth = None;
    let mut max_delegation_ttl = None;

    for (k, v) in map {
        match k.as_text() {
            Some("no_delegation") => no_delegation = v.as_bool(),
            Some("max_delegation_depth") => {
                max_delegation_depth = v.as_integer().and_then(|i| u64::try_from(i).ok());
            }
            Some("max_delegation_ttl") => {
                max_delegation_ttl = v.as_integer().and_then(|i| u64::try_from(i).ok());
            }
            _ => {}
        }
    }

    Ok(DelegationCaveats {
        no_delegation,
        max_delegation_depth,
        max_delegation_ttl,
    })
}

impl DelegationCaveats {
    fn to_value(&self) -> entity_ecf::Value {
        use entity_ecf::{text, Value};
        let mut entries = Vec::new();
        if let Some(max_depth) = self.max_delegation_depth {
            entries.push((
                text("max_delegation_depth"),
                entity_ecf::integer(max_depth as i64),
            ));
        }
        if let Some(max_ttl) = self.max_delegation_ttl {
            entries.push((
                text("max_delegation_ttl"),
                entity_ecf::integer(max_ttl as i64),
            ));
        }
        if let Some(nd) = self.no_delegation {
            entries.push((text("no_delegation"), entity_ecf::bool_val(nd)));
        }
        Value::Map(entries)
    }
}

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("capability denied: {0}")]
    Denied(String),

    #[error("invalid capability: {0}")]
    Invalid(String),

    #[error("delegation error: {0}")]
    DelegationError(String),

    #[error("entity error: {0}")]
    EntityError(String),

    #[error("expired capability")]
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_PEER: &str = "2DFfrCdapVgjiNBPRUdNpwKLfLsmUaKHod4jmhakzBDs3W";

    // --- Pattern matching ---

    #[test]
    fn test_matches_pattern_wildcard() {
        assert!(matches_pattern("/peer/anything/at/all", "*"));
        assert!(matches_pattern("anything", "*"));
    }

    #[test]
    fn test_matches_pattern_exact() {
        assert!(matches_pattern("/peer/system/tree", "/peer/system/tree"));
        assert!(!matches_pattern("/peer/system/tree", "/peer/system/handler"));
    }

    #[test]
    fn test_matches_pattern_prefix() {
        assert!(matches_pattern("/peer/system/tree/foo", "/peer/system/tree/*"));
        assert!(matches_pattern("/peer/system/tree/foo/bar", "/peer/system/tree/*"));
        assert!(!matches_pattern("/peer/system/treefoo", "/peer/system/tree/*"));
        assert!(!matches_pattern("/peer/system/tree", "/peer/system/tree/*"));
    }

    #[test]
    fn test_matches_pattern_peer_wildcard() {
        assert!(matches_pattern("/somepeer/system/tree", "/*/system/tree"));
        assert!(!matches_pattern("system/tree", "/*/system/tree"));
    }

    #[test]
    fn test_matches_pattern_double_peer_wildcard() {
        // /*/*  matches any peer, any path
        assert!(matches_pattern("/peer/system/tree", "/*/*"));
        assert!(matches_pattern("/otherpeer/anything", "/*/*"));
    }

    #[test]
    fn test_matches_pattern_peer_wildcard_subtree() {
        // /*/system/* matches any peer, subtree under system/
        assert!(matches_pattern("/peer/system/tree", "/*/system/*"));
        assert!(matches_pattern("/peer/system/handler/foo", "/*/system/*"));
        assert!(!matches_pattern("/peer/local/files", "/*/system/*"));
    }

    // --- Canonicalize ---

    #[test]
    fn test_canonicalize_wildcard() {
        assert_eq!(
            canonicalize("*", LOCAL_PEER),
            Some(format!("/{}/*", LOCAL_PEER))
        );
    }

    #[test]
    fn test_canonicalize_absolute_peer_wildcard() {
        assert_eq!(
            canonicalize("/*/system/tree", LOCAL_PEER).as_deref(),
            Some("/*/system/tree")
        );
    }

    #[test]
    fn test_canonicalize_rejects_bare_star_slash() {
        // Fail-closed (§1.11): ambiguous `*/rest` → None, never a panic.
        assert!(canonicalize("*/system/tree", LOCAL_PEER).is_none());
    }

    #[test]
    fn test_canonicalize_rejects_dot_slash() {
        // Fail-closed (§1.11): reserved `./` and `../` → None, never a panic.
        assert!(canonicalize("./relative", LOCAL_PEER).is_none());
        assert!(canonicalize("../escape", LOCAL_PEER).is_none());
    }

    #[test]
    fn test_canonicalize_bare_path() {
        assert_eq!(
            canonicalize("system/tree", LOCAL_PEER),
            Some(format!("/{}/system/tree", LOCAL_PEER))
        );
    }

    #[test]
    fn test_canonicalize_already_absolute() {
        let path = format!("/{}/system/tree", LOCAL_PEER);
        assert_eq!(canonicalize(&path, LOCAL_PEER).as_deref(), Some(path.as_str()));
    }

    // --- matches_scope ---

    #[test]
    fn test_matches_scope_basic() {
        assert!(matches_scope(
            "get",
            &["*".into()],
            &[],
            LOCAL_PEER,
        ));
        assert!(matches_scope(
            "get",
            &["get".into(), "put".into()],
            &[],
            LOCAL_PEER,
        ));
        assert!(!matches_scope(
            "delete",
            &["get".into(), "put".into()],
            &[],
            LOCAL_PEER,
        ));
    }

    #[test]
    fn test_matches_scope_with_exclude() {
        // After canonicalization, paths become absolute — exclude still works
        assert!(!matches_scope(
            "system/tree/secret",
            &["system/tree/*".into()],
            &["system/tree/secret".into()],
            LOCAL_PEER,
        ));
    }

    // --- check_permission ---

    fn make_grant(handlers: &[&str], resources: &[&str], ops: &[&str]) -> GrantEntry {
        GrantEntry {
            handlers: PathScope::new(handlers.iter().map(|s| s.to_string()).collect()),
            resources: PathScope::new(resources.iter().map(|s| s.to_string()).collect()),
            operations: IdScope::new(ops.iter().map(|s| s.to_string()).collect()),
            peers: None,
            constraints: None,
            allowances: None,
        }
    }

    fn make_token(grants: Vec<GrantEntry>) -> CapabilityToken {
        CapabilityToken {
            grants,
            granter: Granter::Single(Hash::zero()),
            grantee: Hash::zero(),
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        }
    }

    #[test]
    fn test_check_permission_simple() {
        let token = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        assert!(check_permission("get", "system/tree", LOCAL_PEER, None, &token, LOCAL_PEER));
        assert!(!check_permission("put", "system/tree", LOCAL_PEER, None, &token, LOCAL_PEER));
    }

    #[test]
    fn test_check_permission_wildcard_handlers() {
        let token = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        assert!(check_permission("get", "system/tree", LOCAL_PEER, None, &token, LOCAL_PEER));
        assert!(check_permission("put", "system/handler", LOCAL_PEER, None, &token, LOCAL_PEER));
    }

    #[test]
    fn test_check_permission_wrong_handler() {
        let token = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        assert!(!check_permission("get", "system/handler", LOCAL_PEER, None, &token, LOCAL_PEER));
    }

    #[test]
    fn test_check_permission_with_resource() {
        let token = make_token(vec![make_grant(
            &["system/tree"],
            &["system/type/*"],
            &["get"],
        )]);
        let rt = ResourceTarget {
            targets: vec!["system/type/foo".into()],
            exclude: vec![],
        };
        assert!(check_permission("get", "system/tree", LOCAL_PEER, Some(&rt), &token, LOCAL_PEER));

        let rt_bad = ResourceTarget {
            targets: vec!["system/handler/foo".into()],
            exclude: vec![],
        };
        assert!(!check_permission("get", "system/tree", LOCAL_PEER, Some(&rt_bad), &token, LOCAL_PEER));
    }

    #[test]
    fn test_check_permission_multiple_grants() {
        let token = make_token(vec![
            make_grant(&["system/tree"], &["*"], &["get"]),
            make_grant(&["system/capability"], &[], &["request"]),
        ]);
        assert!(check_permission("get", "system/tree", LOCAL_PEER, None, &token, LOCAL_PEER));
        assert!(check_permission("request", "system/capability", LOCAL_PEER, None, &token, LOCAL_PEER));
    }

    /// R-5 (CROSS-IMPL-ACME-RUST): a grant whose resources use
    /// the bare `*` wildcard does NOT cover paths in other peers' namespaces
    /// (canonicalize maps `*` → `/{local}/*`). Cross-namespace coverage
    /// requires the explicit peer-wildcard form `/*/*`. This test pins the
    /// distinction so future grant constructors don't drift.
    #[test]
    fn test_resource_wildcard_local_vs_cross_namespace() {
        // Bare `*` — local-namespace-only.
        let local_only_token = make_token(vec![make_grant(
            &["system/tree"],
            &["*"],
            &["put"],
        )]);
        let local_target = ResourceTarget {
            targets: vec![format!("/{}/system/foo", LOCAL_PEER)],
            exclude: vec![],
        };
        let cross_target = ResourceTarget {
            targets: vec!["/some-other-peer/system/signature/abc".into()],
            exclude: vec![],
        };
        assert!(
            check_permission("put", "system/tree", LOCAL_PEER, Some(&local_target), &local_only_token, LOCAL_PEER),
            "bare `*` covers local-namespace paths"
        );
        assert!(
            !check_permission("put", "system/tree", LOCAL_PEER, Some(&cross_target), &local_only_token, LOCAL_PEER),
            "bare `*` MUST NOT cover other-peer namespaces"
        );

        // Explicit `/*/*` — cross-namespace.
        let cross_token = make_token(vec![make_grant(
            &["system/tree"],
            &["/*/*"],
            &["put"],
        )]);
        assert!(
            check_permission("put", "system/tree", LOCAL_PEER, Some(&cross_target), &cross_token, LOCAL_PEER),
            "/*/* MUST cover any peer namespace (V7 §6.5 invariant pointer)"
        );
    }

    /// R-5 conformance: `debug_open_grants` MUST authorize tree:put to
    /// signature paths under any peer namespace. The pre-R-5 shape used
    /// bare `*` for resources, which canonicalized to local-only and
    /// rejected cross-namespace writes the test driver issues.
    #[test]
    fn test_debug_open_grants_authorizes_cross_namespace_signature_writes() {
        let token = make_token(debug_open_grants());
        let rt = ResourceTarget {
            targets: vec![format!("/some-ephemeral-peer/system/signature/abcdef")],
            exclude: vec![],
        };
        assert!(
            check_permission("put", "system/tree", LOCAL_PEER, Some(&rt), &token, LOCAL_PEER),
            "R-5: --debug-grants MUST permit cross-namespace tree:put"
        );
    }

    // --- Resource scope checking ---

    #[test]
    fn test_check_resource_scope_simple() {
        let rt = ResourceTarget {
            targets: vec!["system/type/foo".into()],
            exclude: vec![],
        };
        let scope = PathScope::new(vec!["system/type/*".into()]);
        assert!(check_resource_scope(&rt, &scope, LOCAL_PEER, LOCAL_PEER));
    }

    #[test]
    fn test_check_resource_scope_denied() {
        let rt = ResourceTarget {
            targets: vec!["system/handler/foo".into()],
            exclude: vec![],
        };
        let scope = PathScope::new(vec!["system/type/*".into()]);
        assert!(!check_resource_scope(&rt, &scope, LOCAL_PEER, LOCAL_PEER));
    }

    #[test]
    fn test_check_resource_scope_with_grant_exclude() {
        let rt = ResourceTarget {
            targets: vec!["system/type/secret".into()],
            exclude: vec![],
        };
        let scope = PathScope::with_exclude(
            vec!["system/type/*".into()],
            vec!["system/type/secret".into()],
        );
        assert!(!check_resource_scope(&rt, &scope, LOCAL_PEER, LOCAL_PEER));
    }

    /// V7 §5.5 / PR-8 (v7.73 V2(a) shape): a cap's bare `*` resource pattern
    /// canonicalizes against the *granter's* namespace, not the verifier's.
    /// A foreign-granted bare-`*` cap MUST NOT cover a target in the verifier's
    /// namespace; the same cap self-issued (granter == verifier) DOES.
    #[test]
    fn test_check_resource_scope_pr8_granter_frame() {
        // Any peer-id distinct from LOCAL_PEER; canonicalize only string-formats it.
        const FOREIGN_GRANTER: &str = "9aBcDeFgHiJkLmNoPqRsTuVwXyZabcdefghijkLmNoPqRsTu";
        let scope = PathScope::new(vec!["*".into()]); // peer-local-of-granter
        let rt = ResourceTarget {
            targets: vec!["system/type/system/peer".into()], // bare → verifier (local) frame
            exclude: vec![],
        };
        // Foreign granter: grant `*` → /{FOREIGN}/*, target → /{LOCAL}/... → DENY.
        assert!(
            !check_resource_scope(&rt, &scope, LOCAL_PEER, FOREIGN_GRANTER),
            "foreign-granted bare-* cap must not reach the verifier's namespace (PR-8)"
        );
        // Self-issued: grant `*` → /{LOCAL}/*, covers the local-frame target → ALLOW.
        assert!(
            check_resource_scope(&rt, &scope, LOCAL_PEER, LOCAL_PEER),
            "self-issued bare-* cap covers the local namespace"
        );
    }

    /// Fail-closed (V7 §1.11, F5): a malformed resource pattern in a grant
    /// MUST yield a clean DENY, never a panic / dropped connection. Covers
    /// every dimension — a malformed include, a malformed exclude, and a
    /// malformed requested target each deny rather than crash.
    #[test]
    fn test_malformed_pattern_fails_closed() {
        let target = ResourceTarget {
            targets: vec!["system/type/foo".into()],
            exclude: vec![],
        };

        // Malformed resource include in the grant → cannot grant (previously
        // panicked inside canonicalize, dropping the connection).
        let bad_include = make_token(vec![make_grant(&["system/tree"], &["../escape/*"], &["get"])]);
        assert!(!check_permission(
            "get", "system/tree", LOCAL_PEER, Some(&target), &bad_include, LOCAL_PEER
        ));

        // Malformed resource exclude in the grant → fails closed (deny),
        // never under-excludes into an accidental allow.
        let scope = PathScope::with_exclude(
            vec!["system/type/*".into()],
            vec!["*/sneaky".into()],
        );
        assert!(!check_resource_scope(&target, &scope, LOCAL_PEER, LOCAL_PEER));

        // Malformed handler exclude → fails closed at the operation/handler
        // dimension too (no resource target needed).
        let mut grant = make_grant(&["system/tree"], &["*"], &["get"]);
        grant.handlers.exclude = vec!["*/sneaky".into()];
        let bad_handler_exclude = make_token(vec![grant]);
        assert!(!check_permission(
            "get", "system/tree", LOCAL_PEER, None, &bad_handler_exclude, LOCAL_PEER
        ));

        // Malformed requested resource target → deny, not panic.
        let good = make_token(vec![make_grant(&["system/tree"], &["system/type/*"], &["get"])]);
        let bad_target = ResourceTarget {
            targets: vec!["../escape".into()],
            exclude: vec![],
        };
        assert!(!check_resource_scope(&bad_target, &good.grants[0].resources, LOCAL_PEER, LOCAL_PEER));
    }

    // --- Attenuation ---

    #[test]
    fn test_is_attenuated_same_scope() {
        let parent = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        let child = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        assert!(is_attenuated(&child, &parent, LOCAL_PEER));
    }

    #[test]
    fn test_is_attenuated_amplification_denied() {
        let parent = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        let child = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        assert!(!is_attenuated(&child, &parent, LOCAL_PEER));
    }

    #[test]
    fn test_is_attenuated_expiration() {
        let mut parent = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        parent.expires_at = Some(1000);

        let mut child = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        child.expires_at = Some(500);
        assert!(is_attenuated(&child, &parent, LOCAL_PEER));

        child.expires_at = Some(2000);
        assert!(!is_attenuated(&child, &parent, LOCAL_PEER));

        child.expires_at = None; // infinite child, finite parent
        assert!(!is_attenuated(&child, &parent, LOCAL_PEER));
    }

    #[test]
    fn test_is_attenuated_split_grants() {
        let parent = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        // Child splits into two narrower grants — this is valid
        let child = make_token(vec![
            make_grant(&["system/tree"], &["*"], &["get"]),
            make_grant(&["system/handler"], &["*"], &["register"]),
        ]);
        assert!(is_attenuated(&child, &parent, LOCAL_PEER));
    }

    // --- Delegation caveats ---

    #[test]
    fn test_delegation_caveats_none() {
        let parent = make_token(vec![]);
        let child = make_token(vec![]);
        assert!(check_delegation_caveats(&parent, &child, 0));
    }

    #[test]
    fn test_delegation_caveats_no_delegation() {
        let mut parent = make_token(vec![]);
        parent.delegation_caveats = Some(DelegationCaveats {
            no_delegation: Some(true),
            max_delegation_depth: None,
            max_delegation_ttl: None,
        });
        assert!(!check_delegation_caveats(&parent, &make_token(vec![]), 0));
    }

    #[test]
    fn test_delegation_caveats_max_depth() {
        let mut parent = make_token(vec![]);
        parent.delegation_caveats = Some(DelegationCaveats {
            no_delegation: None,
            max_delegation_depth: Some(1),
            max_delegation_ttl: None,
        });
        assert!(check_delegation_caveats(&parent, &make_token(vec![]), 0));
        assert!(!check_delegation_caveats(&parent, &make_token(vec![]), 1));
    }

    #[test]
    fn test_delegation_caveats_max_ttl() {
        let mut parent = make_token(vec![]);
        parent.delegation_caveats = Some(DelegationCaveats {
            no_delegation: None,
            max_delegation_depth: None,
            max_delegation_ttl: Some(3_600_000),
        });

        let mut child = make_token(vec![]);
        child.created_at = 1000;
        child.expires_at = Some(1000 + 3_600_000);
        assert!(check_delegation_caveats(&parent, &child, 0));

        child.expires_at = Some(1000 + 7_200_000);
        assert!(!check_delegation_caveats(&parent, &child, 0));

        child.expires_at = None; // infinite
        assert!(!check_delegation_caveats(&parent, &child, 0));
    }

    // --- Token encoding ---

    #[test]
    fn test_capability_token_to_entity() {
        let token = make_token(vec![make_grant(&["system/tree"], &["*"], &["get"])]);
        let entity = token.to_entity().unwrap();
        assert_eq!(entity.entity_type, entity_types::TYPE_CAP_TOKEN);
        assert!(entity.validate().is_ok());
    }

    #[test]
    fn test_capability_token_roundtrip() {
        let granter = Hash::compute("system/peer", &[1, 2, 3]);
        let grantee = Hash::compute("system/peer", &[4, 5, 6]);
        let parent = Hash::compute("system/capability/token", &[7, 8, 9]);

        let token = CapabilityToken {
            grants: vec![
                GrantEntry {
                    handlers: PathScope::new(vec!["system/tree".into()]),
                    resources: PathScope::with_exclude(
                        vec!["system/type/*".into()],
                        vec!["system/type/secret".into()],
                    ),
                    operations: IdScope::new(vec!["get".into(), "put".into()]),
                    peers: Some(IdScope::new(vec!["*".into()])),
                    constraints: None,
                    allowances: None,
                },
                GrantEntry {
                    handlers: PathScope::new(vec!["system/capability".into()]),
                    resources: PathScope::none(),
                    operations: IdScope::new(vec!["request".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                },
            ],
            granter: Granter::Single(granter),
            grantee,
            parent: Some(parent),
            created_at: 1710000000,
            expires_at: Some(1710003600),
            not_before: Some(1710000000),
            delegation_caveats: Some(DelegationCaveats {
                no_delegation: Some(false),
                max_delegation_depth: Some(3),
                max_delegation_ttl: Some(86400000),
            }),
        };

        let entity = token.to_entity().unwrap();
        let decoded = CapabilityToken::from_entity(&entity).unwrap();

        assert_eq!(decoded.grants, token.grants);
        assert_eq!(decoded.granter, token.granter);
        assert_eq!(decoded.grantee, token.grantee);
        assert_eq!(decoded.parent, token.parent);
        assert_eq!(decoded.created_at, token.created_at);
        assert_eq!(decoded.expires_at, token.expires_at);
        assert_eq!(decoded.not_before, token.not_before);
        assert_eq!(decoded.delegation_caveats, token.delegation_caveats);
    }

    #[test]
    fn test_capability_token_roundtrip_minimal() {
        let token = make_token(vec![make_grant(&["*"], &["*"], &["*"])]);
        let entity = token.to_entity().unwrap();
        let decoded = CapabilityToken::from_entity(&entity).unwrap();
        assert_eq!(decoded.grants, token.grants);
        assert_eq!(decoded.granter, token.granter);
        assert_eq!(decoded.grantee, token.grantee);
        assert_eq!(decoded.parent, token.parent);
        assert_eq!(decoded.created_at, token.created_at);
        assert_eq!(decoded.expires_at, token.expires_at);
        assert_eq!(decoded.delegation_caveats, token.delegation_caveats);
    }

    #[test]
    fn test_capability_token_from_entity_wrong_type() {
        let entity = entity_entity::Entity::new(
            "system/wrong",
            entity_ecf::to_ecf(&entity_ecf::text("test")),
        )
        .unwrap();
        assert!(CapabilityToken::from_entity(&entity).is_err());
    }
}
