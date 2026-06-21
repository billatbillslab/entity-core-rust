//! `@<alias>/...` path expansion.
//!
//! Lifted from egui's `src/views/shell/model.rs::expand_alias` /
//! `lookup_alias`. App-tier `&Peers` calls replaced with crate-tier
//! `&dyn PeerBinding` method calls; semantics unchanged.

use crate::binding::PeerBinding;

/// Expand a `@alias/...` path prefix to `/{peer_id}/...`. Non-alias
/// inputs are returned unchanged. Returns `Err` with a user-facing
/// message when the alias doesn't resolve to any known peer.
///
/// Reserved aliases:
/// - `@self` — the bound peer (this shell's peer).
/// - `@primary` / `@system` / `@default` — the primary peer.
///
/// Otherwise lookup order: case-insensitive label match against
/// `PeerBinding::peer_label` over local + connected peers; then
/// peer-id prefix match. First hit wins.
pub fn expand(input: &str, binding: &dyn PeerBinding) -> Result<String, String> {
    if !input.starts_with('@') {
        return Ok(input.to_string());
    }
    let split = input.find('/').unwrap_or(input.len());
    let alias = &input[1..split];
    let suffix = &input[split..];
    if alias.is_empty() {
        return Err("expected @<alias>... after '@'".into());
    }
    let pid =
        lookup(alias, binding).ok_or_else(|| format!("unknown peer alias: @{}", alias))?;
    let suffix_norm = if suffix.is_empty() { "/" } else { suffix };
    Ok(format!("/{}{}", pid, suffix_norm))
}

/// Resolve a `@<alias>` token to a **bare peer-id** (no leading slash,
/// no trailing slash) for use in identifier-position contexts —
/// `peer delete @foo`, `open Shell @primary`, `disconnect @bob` (per
/// guide §6.2 "standalone @alias"). Distinct from `expand`, which
/// returns the *path-form* expansion for use in path-position contexts.
///
/// Non-alias inputs (no leading `@`) pass through unchanged — callers
/// can use this helper indiscriminately on identifier args; the
/// expansion is only triggered when the input starts with `@`.
///
/// Rejects `@alias/...` forms (paths in identifier position is a
/// usage error — e.g., `peer delete @alice/foo` is ambiguous and
/// should be surfaced rather than silently flattened).
pub fn resolve_pid(input: &str, binding: &dyn PeerBinding) -> Result<String, String> {
    if !input.starts_with('@') {
        return Ok(input.to_string());
    }
    if input.contains('/') {
        return Err(format!(
            "expected peer reference, got path-form '{}' (use a bare @alias or peer-id here)",
            input
        ));
    }
    let alias = &input[1..];
    if alias.is_empty() {
        return Err("expected @<alias> after '@'".into());
    }
    lookup(alias, binding).ok_or_else(|| format!("unknown peer alias: @{}", alias))
}

/// Reverse-direction lookup: given a peer-id, find a display label for
/// it (guide §6.5 pwd display). Returns the peer's label if set;
/// otherwise `None`. Reserved-name aliases (`@self`, `@primary`,
/// `@system`, `@default`) are intentionally NOT returned — they are
/// navigation conveniences, not display conventions. Users with no
/// label set see the resolved peer-id form, which is the unambiguous
/// reference.
pub fn reverse_lookup(pid: &str, binding: &dyn PeerBinding) -> Option<String> {
    binding
        .peer_label(pid)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
}

/// Resolve `alias` (without the leading `@`) to a peer id, or `None`.
pub fn lookup(alias: &str, binding: &dyn PeerBinding) -> Option<String> {
    let lower = alias.to_ascii_lowercase();
    if lower == "self" {
        return Some(binding.peer_id().to_string());
    }
    if lower == "primary" || lower == "system" || lower == "default" {
        return Some(binding.primary_peer_id());
    }
    let mut candidates = binding.peer_ids();
    candidates.extend(binding.connected_peers());
    // Label match (case-insensitive).
    for pid in &candidates {
        let label = binding
            .peer_label(pid)
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty());
        if let Some(l) = label {
            if l.eq_ignore_ascii_case(alias) {
                return Some(pid.clone());
            }
        }
    }
    // Fallback: peer-id prefix match.
    candidates.into_iter().find(|pid| pid.starts_with(alias))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct StubBinding {
        bound: String,
        primary: String,
        peers: Vec<String>,
        remotes: Vec<String>,
        labels: HashMap<String, String>,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.bound }
        fn primary_peer_id(&self) -> String { self.primary.clone() }
        fn peer_ids(&self) -> Vec<String> { self.peers.clone() }
        fn connected_peers(&self) -> Vec<String> { self.remotes.clone() }
        fn peer_label(&self, pid: &str) -> Option<String> {
            self.labels.get(pid).cloned()
        }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<crate::binding::TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<crate::binding::EntityRead> {
            None
        }
    }

    fn stub() -> StubBinding {
        let mut labels = HashMap::new();
        labels.insert("alice_pid".into(), "Alice".into());
        StubBinding {
            bound: "bob_pid".into(),
            primary: "primary_pid".into(),
            peers: vec!["primary_pid".into(), "bob_pid".into(), "alice_pid".into()],
            remotes: vec!["remote_pid".into()],
            labels,
        }
    }

    #[test]
    fn non_alias_pass_through() {
        let b = stub();
        assert_eq!(expand("/bob/foo", &b).unwrap(), "/bob/foo");
        assert_eq!(expand("foo/bar", &b).unwrap(), "foo/bar");
    }

    #[test]
    fn self_resolves_to_bound_peer() {
        let b = stub();
        assert_eq!(expand("@self/foo", &b).unwrap(), "/bob_pid/foo");
        assert_eq!(expand("@self", &b).unwrap(), "/bob_pid/");
    }

    #[test]
    fn primary_aliases_resolve_to_primary() {
        let b = stub();
        assert_eq!(expand("@primary/x", &b).unwrap(), "/primary_pid/x");
        assert_eq!(expand("@system/x", &b).unwrap(), "/primary_pid/x");
        assert_eq!(expand("@default/x", &b).unwrap(), "/primary_pid/x");
    }

    #[test]
    fn label_match_is_case_insensitive() {
        let b = stub();
        assert_eq!(expand("@alice/x", &b).unwrap(), "/alice_pid/x");
        assert_eq!(expand("@ALICE/x", &b).unwrap(), "/alice_pid/x");
    }

    #[test]
    fn prefix_match_fallback() {
        let b = stub();
        // remote_pid starts with "remote"
        assert_eq!(expand("@remote/x", &b).unwrap(), "/remote_pid/x");
    }

    #[test]
    fn unknown_alias_errors() {
        let b = stub();
        assert!(expand("@nobody/x", &b).is_err());
    }

    #[test]
    fn bare_at_errors() {
        let b = stub();
        assert!(expand("@", &b).is_err());
    }

    #[test]
    fn resolve_pid_returns_bare_identifier() {
        let b = stub();
        assert_eq!(resolve_pid("@self", &b).unwrap(), "bob_pid");
        assert_eq!(resolve_pid("@primary", &b).unwrap(), "primary_pid");
        assert_eq!(resolve_pid("@alice", &b).unwrap(), "alice_pid");
    }

    #[test]
    fn resolve_pid_passes_through_non_aliases() {
        let b = stub();
        assert_eq!(resolve_pid("bob_pid", &b).unwrap(), "bob_pid");
        assert_eq!(resolve_pid("anything", &b).unwrap(), "anything");
    }

    #[test]
    fn resolve_pid_rejects_paths() {
        let b = stub();
        assert!(resolve_pid("@alice/foo", &b).is_err());
        assert!(resolve_pid("@self/", &b).is_err());
    }

    #[test]
    fn reverse_lookup_returns_label() {
        let b = stub();
        assert_eq!(reverse_lookup("alice_pid", &b).as_deref(), Some("Alice"));
    }

    #[test]
    fn reverse_lookup_none_when_no_label() {
        let b = stub();
        assert!(reverse_lookup("bob_pid", &b).is_none());
        assert!(reverse_lookup("nonexistent_pid", &b).is_none());
    }
}
