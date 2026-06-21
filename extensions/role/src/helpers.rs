//! Shared helpers for the role extension (EXTENSION-ROLE v1.5 §6.2, §5.2).
//!
//! - `is_excluded` — single tree-get used by the runtime assign path
//!   (§4.3 step 4b) and the bootstrap L0 path (§4.5). Per §1.5 RI3 this
//!   helper MUST return a defined answer regardless of bootstrap ordering;
//!   a missing exclusion entity returns `false`.
//! - `resolve_grant_templates` — substitutes `{context}` and `{peer_id}`
//!   into all path-shaped fields of a grant entry per §5.2.

use std::sync::Arc;

use entity_capability::{GrantEntry, IdScope, PathScope};
use entity_store::LocationIndex;

use crate::paths::{path_role_exclusion, resolve_template_str};

/// `is_excluded(context, peer_id)` per §6.2. A single tree lookup; returns
/// `true` iff an exclusion entity is bound at
/// `[/{local_peer}/]system/role/{context}/excluded/{peer_id}`.
///
/// Caller passes the qualified path prefix (`/{local_peer_id}/`); supplying
/// an empty prefix yields a bare-path lookup (unit-test convenience).
pub fn is_excluded(
    location_index: &Arc<dyn LocationIndex>,
    qualified_prefix: &str,
    context: &str,
    peer_id: &str,
) -> bool {
    let path = format!(
        "{}{}",
        qualified_prefix,
        path_role_exclusion(context, peer_id)
    );
    location_index.get(&path).is_some()
}

/// Resolve `{context}` and `{peer_id}` template variables in every path
/// string of a grant entry per §5.2. Pure textual substitution — no path
/// canonicalization or validation.
pub fn resolve_grant_templates(
    grant: &GrantEntry,
    context: &str,
    peer_id: &str,
) -> GrantEntry {
    GrantEntry {
        handlers: resolve_path_scope(&grant.handlers, context, peer_id),
        resources: resolve_path_scope(&grant.resources, context, peer_id),
        operations: resolve_id_scope(&grant.operations, context, peer_id),
        peers: grant
            .peers
            .as_ref()
            .map(|p| resolve_id_scope(p, context, peer_id)),
        constraints: grant.constraints.clone(),
        allowances: grant.allowances.clone(),
    }
}

fn resolve_path_scope(scope: &PathScope, context: &str, peer_id: &str) -> PathScope {
    PathScope::with_exclude(
        scope
            .include
            .iter()
            .map(|s| resolve_template_str(s, context, peer_id))
            .collect(),
        scope
            .exclude
            .iter()
            .map(|s| resolve_template_str(s, context, peer_id))
            .collect(),
    )
}

fn resolve_id_scope(scope: &IdScope, context: &str, peer_id: &str) -> IdScope {
    IdScope::with_exclude(
        scope
            .include
            .iter()
            .map(|s| resolve_template_str(s, context, peer_id))
            .collect(),
        scope
            .exclude
            .iter()
            .map(|s| resolve_template_str(s, context, peer_id))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_hash::Hash;
    use entity_store::MemoryLocationIndex;

    #[test]
    fn is_excluded_reads_qualified_path() {
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let dummy = Hash::compute("system/role/exclusion", b"dummy");
        let prefix = "/peer42/";
        assert!(!is_excluded(&li, prefix, "admin", "alice"));
        li.set("/peer42/system/role/admin/excluded/alice", dummy);
        assert!(is_excluded(&li, prefix, "admin", "alice"));
        assert!(!is_excluded(&li, prefix, "admin", "bob"));
        assert!(!is_excluded(&li, prefix, "other", "alice"));
    }

    #[test]
    fn template_resolution_substitutes_path_scopes() {
        let grant = GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec![
                "shared/{context}/*".into(),
                "by/{peer_id}/*".into(),
            ]),
            operations: IdScope::new(vec!["get".into(), "put".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        };
        let resolved = resolve_grant_templates(&grant, "group/team-alpha", "peerXYZ");
        assert_eq!(resolved.resources.include[0], "shared/group/team-alpha/*");
        assert_eq!(resolved.resources.include[1], "by/peerXYZ/*");
    }

    #[test]
    fn template_resolution_substitutes_id_scopes() {
        let grant = GrantEntry {
            handlers: PathScope::new(vec!["*".into()]),
            resources: PathScope::new(vec![]),
            operations: IdScope::new(vec!["op-{context}".into()]),
            peers: Some(IdScope::new(vec!["{peer_id}".into()])),
            constraints: None,
            allowances: None,
        };
        let resolved = resolve_grant_templates(&grant, "ctx", "peerXYZ");
        assert_eq!(resolved.operations.include[0], "op-ctx");
        assert_eq!(resolved.peers.as_ref().unwrap().include[0], "peerXYZ");
    }
}
