//! Path conventions for `system/role` (EXTENSION-ROLE v1.6 §3, §5.2).
//!
//! All role data lives under `system/role/{context}/...` with four
//! sub-namespaces: role definitions, assignments, exclusions, and
//! derived-token linkage entities. Role-derived capability tokens are
//! pinned at `system/capability/grants/role-derived/{context}/{peer_id_hex}/{token_hash_hex}`
//! per R4.
//!
//! **Encoding rule (v1.6 SI-1).** Path-segment `{peer_id}` and
//! template-variable `{peer_id}` both substitute to lowercase hex of the
//! assignee's `system/hash` (the content hash of the assignee's
//! `system/peer` entity). Base58 PeerID is reserved for the
//! `/{peer_id}/...` universal-root segment only (V7 §1.4); every other
//! peer reference in the system uses hex of `system/hash`.

use entity_hash::Hash;

/// Storage prefix for `system/role` entities (peer-relative).
pub const ROLE_PREFIX: &str = "system/role/";

/// SI-26 / SI-28: reserved path for the deployment's initial-grant
/// policy entity (renamed from v1.5 `system/role/bootstrap-policy`).
pub const PATH_INITIAL_GRANT_POLICY: &str = "system/role/initial-grant-policy";

// ---------------------------------------------------------------------------
// Peer-ID encoding (v1.6 SI-1)
// ---------------------------------------------------------------------------

/// Encode a `system/hash` (content hash of an assignee's identity entity)
/// as the lowercase-hex path segment used in role-extension paths.
/// 33-byte format-coded hash → 66 hex characters.
pub fn peer_segment_from_hash(h: &Hash) -> String {
    let bytes = h.to_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Inverse of `peer_segment_from_hash`. Returns `None` for malformed
/// segments (wrong length, non-hex characters, or an algorithm byte the
/// `Hash` constructor rejects).
pub fn hash_from_peer_segment(seg: &str) -> Option<Hash> {
    if seg.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(seg.len() / 2);
    let chars: Vec<char> = seg.chars().collect();
    for pair in chars.chunks(2) {
        let s: String = pair.iter().collect();
        let b = u8::from_str_radix(&s, 16).ok()?;
        bytes.push(b);
    }
    Hash::from_bytes(&bytes).ok()
}

/// Storage prefix for role-derived capability tokens (per R4, peer-relative).
pub const ROLE_DERIVED_PREFIX: &str = "system/capability/grants/role-derived/";

/// Reserved role names that collide with assignment / exclusion sub-namespaces
/// (per R10 §3.2).
pub const RESERVED_ROLE_NAMES: &[&str] = &["assignment", "excluded"];

/// Path to a role definition: `system/role/{context}/{role_name}`.
pub fn path_role_definition(context: &str, role_name: &str) -> String {
    format!("{}{}/{}", ROLE_PREFIX, context, role_name)
}

/// Path to a role assignment:
/// `system/role/{context}/assignment/{peer_id_hex}/{role_name}` (multi-role per R6).
/// `peer_id_hex` is hex of the assignee's identity-entity `system/hash` per SI-1.
pub fn path_role_assignment(context: &str, peer_id_hex: &str, role_name: &str) -> String {
    format!(
        "{}{}/assignment/{}/{}",
        ROLE_PREFIX, context, peer_id_hex, role_name
    )
}

/// Prefix for all assignments of a given peer in a context (used by sweeps):
/// `system/role/{context}/assignment/{peer_id_hex}/`.
pub fn prefix_role_assignment_peer(context: &str, peer_id_hex: &str) -> String {
    format!("{}{}/assignment/{}/", ROLE_PREFIX, context, peer_id_hex)
}

/// Prefix for all assignments of a role within a context (used by re-derive):
/// `system/role/{context}/assignment/`. Iteration must filter by trailing
/// `{role_name}` since multi-role per peer is permitted.
pub fn prefix_role_assignment(context: &str) -> String {
    format!("{}{}/assignment/", ROLE_PREFIX, context)
}

/// Path to a role exclusion: `system/role/{context}/excluded/{peer_id_hex}`.
pub fn path_role_exclusion(context: &str, peer_id_hex: &str) -> String {
    format!("{}{}/excluded/{}", ROLE_PREFIX, context, peer_id_hex)
}

/// SI-5 v1.6: linkage entity path
/// `system/role/{context}/derived-tokens/{peer_id_hex}/{role_name}`.
/// One per (peer, role, context) tuple under default grace=0; multiple
/// during overlap windows per §5.5.
pub fn path_role_derived_link(
    context: &str,
    peer_id_hex: &str,
    role_name: &str,
) -> String {
    format!(
        "{}{}/derived-tokens/{}/{}",
        ROLE_PREFIX, context, peer_id_hex, role_name
    )
}

/// Prefix for all linkage entities for a (context, peer) pair.
pub fn prefix_role_derived_links_peer(context: &str, peer_id_hex: &str) -> String {
    format!(
        "{}{}/derived-tokens/{}/",
        ROLE_PREFIX, context, peer_id_hex
    )
}

/// Path to a role-derived capability token (per R4):
/// `system/capability/grants/role-derived/{context}/{peer_id_hex}/{token_hash_hex}`.
pub fn path_role_derived_token(
    context: &str,
    peer_id_hex: &str,
    token_hash_hex: &str,
) -> String {
    format!(
        "{}{}/{}/{}",
        ROLE_DERIVED_PREFIX, context, peer_id_hex, token_hash_hex
    )
}

/// Prefix for all role-derived tokens for a (context, peer) pair (sweep target):
/// `system/capability/grants/role-derived/{context}/{peer_id_hex}/`.
pub fn prefix_role_derived_peer(context: &str, peer_id_hex: &str) -> String {
    format!("{}{}/{}/", ROLE_DERIVED_PREFIX, context, peer_id_hex)
}

// ---------------------------------------------------------------------------
// Path decomposition
// ---------------------------------------------------------------------------

/// Decomposed assignment path components. The trailing `role_name` is
/// optional to support `unassign` against the all-roles-for-peer form
/// (§4.4: "the role-omitted form for all roles in the context").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAssignmentPath {
    pub context: String,
    pub peer_id: String,
    pub role_name: Option<String>,
}

/// Decomposed exclusion path components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedExclusionPath {
    pub context: String,
    pub peer_id: String,
}

/// Decomposed role-definition path components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRoleDefPath {
    pub context: String,
    pub role_name: String,
}

/// Strip an optional `/{peer_id}/` qualifier (V7 path qualification).
/// Returns the bare path starting at `system/role/...`.
fn strip_peer_qualifier(path: &str) -> &str {
    let trimmed = path.trim_start_matches('/');
    if let Some(slash) = trimmed.find('/') {
        let head = &trimmed[..slash];
        let rest = &trimmed[slash + 1..];
        // V7 PeerID Base58 is ~44–46 chars; bare paths start with `system`,
        // `app`, etc. Detect peer-qualified by checking for the role prefix
        // in `rest`.
        if rest.starts_with(ROLE_PREFIX) || rest.starts_with(ROLE_DERIVED_PREFIX) {
            return rest;
        }
        // Otherwise the head is part of the bare path (no qualifier).
        // Fall through to treating the original as bare.
        let _ = head;
    }
    trimmed
}

/// Parse `[/<peer>/]system/role/{context}/assignment/{peer_id}[/{role_name}]`.
///
/// Per §4.4, `unassign` accepts both `.../assignment/{peer_id}/{role_name}`
/// (specific role) and `.../assignment/{peer_id}` (all roles). For `assign`,
/// the `role_name` is required by §4.2 path decomposition; the caller
/// validates `role_name.is_some()` at the op boundary.
pub fn parse_assignment_path(path: &str) -> Option<ParsedAssignmentPath> {
    let bare = strip_peer_qualifier(path);
    let rest = bare.strip_prefix(ROLE_PREFIX)?;
    // rest = "{context}/assignment/{peer_id}[/{role_name}]"
    let segs: Vec<&str> = rest.split('/').collect();
    // Need at minimum: <ctx-seg-1> ... "assignment" <peer_id>
    let assignment_idx = segs.iter().position(|s| *s == "assignment")?;
    if assignment_idx == 0 {
        return None;
    }
    if segs.len() < assignment_idx + 2 {
        return None;
    }
    let context = segs[..assignment_idx].join("/");
    let peer_id = segs[assignment_idx + 1].to_string();
    if peer_id.is_empty() {
        return None;
    }
    let role_name = if segs.len() > assignment_idx + 2 {
        let tail = segs[assignment_idx + 2..].join("/");
        if tail.is_empty() {
            None
        } else {
            Some(tail)
        }
    } else {
        None
    };
    Some(ParsedAssignmentPath {
        context,
        peer_id,
        role_name,
    })
}

/// Parse `[/<peer>/]system/role/{context}/excluded/{peer_id}`.
pub fn parse_exclusion_path(path: &str) -> Option<ParsedExclusionPath> {
    let bare = strip_peer_qualifier(path);
    let rest = bare.strip_prefix(ROLE_PREFIX)?;
    let segs: Vec<&str> = rest.split('/').collect();
    let excluded_idx = segs.iter().position(|s| *s == "excluded")?;
    if excluded_idx == 0 {
        return None;
    }
    if segs.len() != excluded_idx + 2 {
        return None;
    }
    let context = segs[..excluded_idx].join("/");
    let peer_id = segs[excluded_idx + 1].to_string();
    if peer_id.is_empty() {
        return None;
    }
    Some(ParsedExclusionPath { context, peer_id })
}

/// Parse `[/<peer>/]system/role/{context}/{role_name}`. Rejects role names
/// that collide with the `assignment/` or `excluded/` sub-namespaces (R10).
pub fn parse_role_definition_path(path: &str) -> Option<ParsedRoleDefPath> {
    let bare = strip_peer_qualifier(path);
    let rest = bare.strip_prefix(ROLE_PREFIX)?;
    let segs: Vec<&str> = rest.split('/').collect();
    if segs.len() < 2 {
        return None;
    }
    // Last segment is role_name; preceding segments are context.
    let role_name = segs[segs.len() - 1].to_string();
    if role_name.is_empty() {
        return None;
    }
    if RESERVED_ROLE_NAMES.contains(&role_name.as_str()) {
        return None;
    }
    let context = segs[..segs.len() - 1].join("/");
    if context.is_empty() {
        return None;
    }
    Some(ParsedRoleDefPath { context, role_name })
}

// ---------------------------------------------------------------------------
// Template resolution (§5.2)
// ---------------------------------------------------------------------------

/// Resolve `{context}` and `{peer_id}` template variables in a path string.
/// Pure textual substitution per §5.2 — no path normalization.
pub fn resolve_template_str(input: &str, context: &str, peer_id: &str) -> String {
    input
        .replace("{context}", context)
        .replace("{peer_id}", peer_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_assignment_with_role() {
        let p = "system/role/group/team-alpha/assignment/abc123/leader";
        let r = parse_assignment_path(p).unwrap();
        assert_eq!(r.context, "group/team-alpha");
        assert_eq!(r.peer_id, "abc123");
        assert_eq!(r.role_name.as_deref(), Some("leader"));
    }

    #[test]
    fn parse_assignment_without_role() {
        let p = "system/role/admin/assignment/peerXYZ";
        let r = parse_assignment_path(p).unwrap();
        assert_eq!(r.context, "admin");
        assert_eq!(r.peer_id, "peerXYZ");
        assert_eq!(r.role_name, None);
    }

    #[test]
    fn parse_assignment_with_peer_qualifier() {
        let p = "/localPeerID42/system/role/admin/assignment/peerXYZ/operator";
        let r = parse_assignment_path(p).unwrap();
        assert_eq!(r.context, "admin");
        assert_eq!(r.peer_id, "peerXYZ");
        assert_eq!(r.role_name.as_deref(), Some("operator"));
    }

    #[test]
    fn parse_assignment_rejects_missing_peer() {
        assert!(parse_assignment_path("system/role/admin/assignment").is_none());
        assert!(parse_assignment_path("system/role/admin/assignment/").is_none());
    }

    #[test]
    fn parse_exclusion_path_basic() {
        let p = "system/role/group/team/excluded/abc";
        let r = parse_exclusion_path(p).unwrap();
        assert_eq!(r.context, "group/team");
        assert_eq!(r.peer_id, "abc");
    }

    #[test]
    fn parse_exclusion_rejects_extra_segments() {
        assert!(parse_exclusion_path("system/role/admin/excluded/peerX/extra").is_none());
    }

    #[test]
    fn parse_role_definition_basic() {
        let p = "system/role/group/team-alpha/leader";
        let r = parse_role_definition_path(p).unwrap();
        assert_eq!(r.context, "group/team-alpha");
        assert_eq!(r.role_name, "leader");
    }

    #[test]
    fn parse_role_definition_rejects_reserved_names() {
        assert!(parse_role_definition_path("system/role/admin/assignment").is_none());
        assert!(parse_role_definition_path("system/role/admin/excluded").is_none());
    }

    #[test]
    fn parse_role_definition_requires_context_and_name() {
        assert!(parse_role_definition_path("system/role/").is_none());
        assert!(parse_role_definition_path("system/role/onlyone").is_none());
    }

    #[test]
    fn resolve_template_substitutes_both_vars() {
        let resolved = resolve_template_str(
            "shared/{context}/by/{peer_id}/data",
            "group/team-alpha",
            "peer-Base58-XYZ",
        );
        assert_eq!(resolved, "shared/group/team-alpha/by/peer-Base58-XYZ/data");
    }

    #[test]
    fn resolve_template_no_vars_passes_through() {
        let resolved = resolve_template_str("public/static", "ctx", "peer");
        assert_eq!(resolved, "public/static");
    }

    #[test]
    fn path_helpers_match_spec_examples() {
        // v1.6: peer_id segments are hex-of-system/hash, not Base58.
        // We use short stand-in tokens here for readability; production
        // use passes the 66-char output of `peer_segment_from_hash`.
        assert_eq!(
            path_role_definition("admin", "operator"),
            "system/role/admin/operator"
        );
        assert_eq!(
            path_role_assignment("admin", "00aa", "operator"),
            "system/role/admin/assignment/00aa/operator"
        );
        assert_eq!(
            path_role_exclusion("group/team-alpha", "00aa"),
            "system/role/group/team-alpha/excluded/00aa"
        );
        assert_eq!(
            path_role_derived_token("group/team-alpha", "00aa", "deadbeef"),
            "system/capability/grants/role-derived/group/team-alpha/00aa/deadbeef"
        );
        assert_eq!(
            path_role_derived_link("group/team-alpha", "00aa", "leader"),
            "system/role/group/team-alpha/derived-tokens/00aa/leader"
        );
    }

    #[test]
    fn peer_segment_roundtrip_hex() {
        let h = Hash::compute("system/peer", b"alice-stub");
        let seg = peer_segment_from_hash(&h);
        assert_eq!(seg.len(), 66, "ECFv1-SHA-256 hash hex is 66 chars");
        assert!(
            seg.starts_with("00"),
            "format byte 0x00 prefixes the hex segment"
        );
        let back = hash_from_peer_segment(&seg).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn hash_from_peer_segment_rejects_garbage() {
        assert!(hash_from_peer_segment("not hex").is_none());
        assert!(hash_from_peer_segment("00").is_none()); // too short
        assert!(hash_from_peer_segment("zz").is_none());
    }
}
