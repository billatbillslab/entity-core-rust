//! Serving-side scope predicates for the `http-poll` content-by-hash
//! route.
//!
//! Per the serving-mode content-scope ruling
//! §1.2: the route's `in_scope(H)` predicate is **the lever** —
//! request-side auth is always hash-knowledge, serving-side scope is
//! where the operator decides which hashes the route answers for. The
//! handler shape is identical across predicates; only the predicate
//! swaps. v1 ships [`NamespaceScope`] (the recommended default per
//! §1.2 — "content-namespace, ship-first"); closure-scope and
//! whole-store land as additional impls without touching the handler.
//!
//! **T4 mitigation (ruling §1.3):** the route returns an identical
//! `404` for both "out of scope" and "not held," so the predicate
//! result is never directly observable as a presence oracle. Honor
//! that contract in any new predicate impl: return `Ok(false)` for
//! anything you don't want to serve, never return an error that the
//! caller might leak as 4xx vs 5xx.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use entity_capability::CapabilityToken;
use entity_hash::Hash;

use crate::PeerShared;

/// The serving-side scope contract. Implementations decide which
/// hashes the content-by-hash route serves **and** which paths the
/// tree-get route serves. Same scope object, two faces — per arch
/// ruling F-PY-12: "the published set has a tree-face
/// (which paths resolve) and a content-face (which hashes resolve),
/// same serve_scope." At the poll boundary there's no protocol cap,
/// so the served scope IS the auth on both faces.
///
/// **Amendment 5 (§6.5.6) — `serve_scope` is a capability token.**
/// The spec normative posture is that `serve_scope` is a literal
/// `system/capability` token evaluated by the same cap evaluator the
/// live-EXECUTE surface uses (`check_permission` / `check_path_permission`)
/// — one ACL machinery, structurally no drift. [`CapTokenScope`] is
/// the recommended-default impl that wraps a `CapabilityToken` and
/// satisfies this contract by construction.
///
/// **Non-`CapTokenScope` impls are a SECOND ACL machinery.** Other
/// `ScopePredicate` impls (closure-walk, federated lookups,
/// whole-store) are valid as implementation extension points BUT MUST
/// be kept in sync with the operator's live-EXECUTE cap set by
/// hand. Use them only when the cap-token shape genuinely cannot
/// express the desired scope; for ordinary published-set serving, use
/// [`CapTokenScope`] and let the cap be the audit log.
///
/// The trait is async because some predicate impls (closure-walk,
/// federated lookups) may need to traverse tree state that isn't
/// strictly synchronous — though the v1 [`NamespaceScope`] is a
/// trivial string-prefix / single-LocationIndex-lookup check.
#[async_trait]
pub trait ScopePredicate: Send + Sync {
    /// **Content-face.** Return `Ok(true)` iff `hash` is in the
    /// published set the operator configured for this listener.
    /// `Ok(false)` for out-of-scope (the canonical "no, don't serve
    /// this" answer). `Err` is reserved for genuine infrastructure
    /// failures (storage errors, lock poison) — never use it for
    /// "this hash isn't served," which is `Ok(false)` per T4.
    async fn in_scope(
        &self,
        hash: &Hash,
        shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError>;

    /// **Tree-face.** Return `Ok(true)` iff `absolute_path` is
    /// within the published set's tree footprint. Used by the
    /// `GET /tree/{path}` poll route. Per F-PY-12: published-scope-
    /// gated, NOT "always 501." Default impl returns `Ok(false)`
    /// (no tree-face by default) — predicate impls that have a
    /// natural path-domain answer override.
    ///
    /// Same T4 contract as `in_scope`: `Ok(false)` for out-of-scope;
    /// `Err` only for infrastructure failures. The caller maps both
    /// `Ok(false)` and not-held into an identical 404.
    async fn in_scope_path(
        &self,
        _absolute_path: &str,
        _shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        Ok(false)
    }

    /// Short human-readable identifier for logging / profile-entity
    /// metadata. e.g. `"namespace(system/content/public)"` or
    /// `"whole-store"`.
    fn describe(&self) -> String;
}

/// Errors a [`ScopePredicate`] may return. Kept intentionally small;
/// per T4 a normal "this hash isn't served" answer is `Ok(false)`,
/// not an error.
#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    #[error("scope storage error: {0}")]
    Storage(String),
}

/// Content-mount scope — serves any hash bound at the EXTENSION-
/// CONTENT mount label under any peer-id top-level in **this local
/// view** of the universal address space (V7 §1.4).
///
/// **The universal-tree model this implements.** Every peer holds a
/// complete local-scoped view of the universal tree. A peer may
/// write into ANY `/{pid}/...` path in their own local view — that's
/// a cache of what they hold about each peer-id's subtree. The
/// keyholder for `{pid}` is the only authority for what's TRUE about
/// `{pid}`; the local peer is the authority for what they choose to
/// CACHE in their own view. The content store is universal (just
/// `hash → bytes`, no namespaces); content-mount labels like
/// `system/content/{ns}` exist only so that cap grants — which are
/// tree-path-keyed — can cover content-store access.
///
/// **What `NamespaceScope("system/content/public")` means at this
/// serving listener.** "Expose any hash bound at
/// `/{any_pid}/system/content/public/{hex(H)}` in my local view."
/// Peer-wildcard *over what I locally hold*, not a claim that the
/// mount label is symmetric across peers — each peer's `public`
/// subtree is their own. If the local view caches a foreign peer's
/// public-namespace binding (e.g. because the operator runs as a
/// mirror), this scope surfaces it; if it doesn't, it doesn't.
/// Authority for content remains the hash itself (content-addressed
/// verify-by-rehash) plus whatever signed manifest is published.
///
/// **For the "serve any stored hash regardless of tree placement"
/// case**, use [`CapTokenScope`] with a wide cap or wait on the
/// `whole-store` explicit-opt-in shape (§6.5.6).
pub struct NamespaceScope {
    /// Content-mount path WITHOUT a leading `/` or trailing `/` —
    /// e.g., `"system/content/public"`. At check time the full
    /// binding path scanned is `/{any_pid}/{namespace}/{hex(H)}`
    /// across the LocationIndex.
    namespace: String,
}

impl NamespaceScope {
    /// Construct a namespace-scope predicate. `namespace` is the
    /// content namespace path (e.g., `"system/content/public"`); it
    /// MUST NOT include a leading `/` or a trailing `/`. The
    /// LocationIndex lookup uses the local peer's ID as the
    /// top-level segment.
    pub fn new(namespace: impl Into<String>) -> Self {
        let mut ns = namespace.into();
        // Tolerate operator-provided leading/trailing slashes; the
        // path we BUILD at check time is precise.
        ns = ns.trim_matches('/').to_string();
        Self { namespace: ns }
    }

    /// The configured namespace (without slashes).
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

#[async_trait]
impl ScopePredicate for NamespaceScope {
    /// Content-face per universal-tree-semantics: `H` is in scope iff
    /// **any** peer-id has a binding at `/{pid}/{namespace}/{hex(H)}`.
    /// Walks `location_index.list("/")` once per query; acceptable for
    /// in-memory stores at any plausible scale. A reverse hash→paths
    /// index would make this O(1) but is not load-bearing.
    async fn in_scope(
        &self,
        hash: &Hash,
        shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        let hex_h = super::hex_encode(&hash.to_bytes());
        // Universal-tree reading: ANY peer's `/{pid}/{namespace}/{hex(H)}`
        // satisfies. We can't enumerate peer-ids without walking the
        // store, but the suffix is invariant — scan for any binding
        // whose path ends with `/{namespace}/{hex_h}` and starts with
        // `/{some_pid}/` followed by `{namespace}/`.
        let suffix = format!("/{}/{}", self.namespace, hex_h);
        for entry in shared.location_index.list("/") {
            if !entry.path.ends_with(&suffix) {
                continue;
            }
            // Confirm the structure is `/{pid}/{namespace}/{hex_h}`:
            // the part before the suffix MUST be just `/{pid}` (no
            // extra segments). This rejects e.g.
            // `/{pid}/something/system/content/public/{hex_h}` where
            // the binding is deeper than the namespace anchor.
            let head = &entry.path[..entry.path.len() - suffix.len()];
            // `head` is `/{pid}`. It must start with `/`, have no
            // further `/`, and be non-empty.
            if !head.starts_with('/') {
                continue;
            }
            if head[1..].contains('/') {
                continue;
            }
            if head.len() <= 1 {
                continue;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Tree-face per universal-tree-semantics: a path `p` is
    /// reachable iff it matches the pattern `/*/{namespace}/...` OR
    /// is an ancestor of any such pattern (so a listing walk from
    /// `/` down to in-scope content surfaces correctly).
    ///
    /// Reading B fix (per audit): foreign peer-ids' subtrees
    /// surface in `peers.list` when they contain in-scope content,
    /// matching the cohort `multi_peer_publish_via_tree_put` test.
    ///
    /// Strict leaf-vs-ancestor disambiguation falls out at the
    /// LocationIndex lookup in `render_leaf` — unbound ancestors
    /// return `None` and yield identical 404 to not-held (T4).
    async fn in_scope_path(
        &self,
        absolute_path: &str,
        _shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        // Universal root is always reachable if anything is published.
        if absolute_path == "/" {
            return Ok(true);
        }

        // Split `absolute_path` into `["", pid_or_anchor, rest...]`.
        // Reject if it doesn't start with `/`.
        let trimmed = match absolute_path.strip_prefix('/') {
            Some(t) => t,
            None => return Ok(false),
        };

        // Segment 0 is the peer-id (or another reserved top-level
        // word; for the purposes of scope, anything in segment 0
        // *could* be a peer-id holding in-scope namespace). Reject
        // empty (which would mean `absolute_path == "/"`, already
        // handled).
        let (seg0, tail) = match trimmed.find('/') {
            Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
            None => (trimmed, ""),
        };
        if seg0.is_empty() {
            return Ok(false);
        }

        // Ancestor case: `p` is `/{pid}` (no namespace suffix yet).
        // Any peer-id is potentially in scope under the universal
        // reading; surface so that descending walks can reach in-
        // scope content.
        if tail.is_empty() {
            return Ok(true);
        }

        // Compare `tail` against the configured namespace.
        if tail == self.namespace {
            // Exact anchor: `/{pid}/{namespace}` → in scope.
            return Ok(true);
        }
        if tail.starts_with(&format!("{}/", self.namespace)) {
            // Descendant of the namespace anchor.
            return Ok(true);
        }
        if self.namespace.starts_with(&format!("{}/", tail)) {
            // Ancestor of the namespace (tail is a path-prefix-of-
            // namespace, e.g. tail = "system" when namespace =
            // "system/content/public"). Surfaces intermediate
            // listings on the walk from `/{pid}` down to the
            // namespace anchor.
            return Ok(true);
        }
        Ok(false)
    }

    fn describe(&self) -> String {
        format!("namespace(/*/{})", self.namespace)
    }
}

// ===========================================================================
// CapTokenScope — Amendment-5 recommended default
// ===========================================================================

/// `serve_scope` as a capability token (EXTENSION-NETWORK §6.5.6
/// Amendment 5). Wraps a [`CapabilityToken`] and routes BOTH faces
/// through `entity_capability::check_permission` — the same evaluator
/// the live-EXECUTE surface uses for `system/tree:get`. This is the
/// **one-ACL-machinery** posture the spec mandates as normative.
///
/// **Tree-face.** `in_scope_path(p)` ⇔ the cap permits
/// `get` on resource `p` against handler `system/tree`. Out-of-scope
/// paths receive identical 404 to not-held (T4).
///
/// **Content-face.** `in_scope(H)` walks the cap's resource includes
/// and asks "does any include namespace bind H?" — i.e., §6.4.2 Hash
/// Tree Presence within the cap's reach. For each include pattern
/// shaped like `/{pid}/{ns}/*`, derive `{ns}` and check
/// LocationIndex for `/{pid}/{ns}/{hex33(H)}`.
///
/// **The cap IS the publish contract.** What you put in the cap is
/// what gets served; nothing else. Audit by inspecting the cap;
/// revoke by re-rendering against a smaller one.
pub struct CapTokenScope {
    cap: CapabilityToken,
}

impl CapTokenScope {
    /// Wrap a published-set capability token. The token's resource
    /// includes are the authoritative published-set membership.
    pub fn new(cap: CapabilityToken) -> Self {
        Self { cap }
    }

    /// The wrapped cap token (for inspection / audit).
    pub fn cap(&self) -> &CapabilityToken {
        &self.cap
    }
}

#[async_trait]
impl ScopePredicate for CapTokenScope {
    /// Content-face per §6.5.6: §6.4.2 Hash Tree Presence within the
    /// cap's reach. For each include namespace, check if there's a
    /// binding at `/{ns}/{hex33(H)}`.
    async fn in_scope(
        &self,
        hash: &Hash,
        shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        let local_pid = shared.keypair.peer_id();
        let hex_h = super::hex_encode(&hash.to_bytes());

        for grant in &self.cap.grants {
            // Only `system/tree:get` grants project to a content
            // namespace under the published-set topology. Other
            // grants (compute, identity, ...) are not in the
            // serving-mode contract here.
            if !grant_allows_tree_get(grant) {
                continue;
            }
            for pat in &grant.resources.include {
                // A malformed pattern can't project to a namespace — skip it.
                let canon = match entity_capability::canonicalize(pat, local_pid.as_str()) {
                    Some(c) => c,
                    None => continue,
                };
                // Derive the namespace prefix from a `prefix/*`
                // pattern; exact patterns aren't a content-namespace.
                let ns_prefix = match canon.strip_suffix("/*") {
                    Some(p) => p.to_string(),
                    None => continue,
                };
                let bind_path = format!("{}/{}", ns_prefix, hex_h);
                if shared.location_index.get(&bind_path).is_some() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Tree-face per §6.5.6: cap permits `system/tree:get` on the
    /// concrete path. Drift impossible — same evaluator the live
    /// surface uses.
    ///
    /// Amendment-5 listing-discovery: a path is also reachable if
    /// it is an **ancestor** of any cap-include pattern (so a
    /// consumer can list from the universal-tree root down to
    /// in-scope content). The strict leaf-vs-ancestor distinction
    /// falls out at the LocationIndex lookup in `render_leaf`.
    async fn in_scope_path(
        &self,
        absolute_path: &str,
        shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        let local_pid = shared.keypair.peer_id();

        // Direct cap eval — same evaluator the live surface uses.
        let target = entity_capability::ResourceTarget {
            targets: vec![absolute_path.to_string()],
            exclude: vec![],
        };
        let allowed = entity_capability::check_permission(
            "get",
            "system/tree",
            local_pid.as_str(),
            Some(&target),
            &self.cap,
            local_pid.as_str(),
        );
        if allowed {
            return Ok(true);
        }

        // Ancestor check: any cap include whose prefix sits under
        // `absolute_path/`? Universal root `/` is reachable as long
        // as any include exists.
        for grant in &self.cap.grants {
            if !grant_allows_tree_get(grant) {
                continue;
            }
            for pat in &grant.resources.include {
                // A malformed pattern can't extend reachability — skip it.
                let canon = match entity_capability::canonicalize(pat, local_pid.as_str()) {
                    Some(c) => c,
                    None => continue,
                };
                let inc_prefix = canon.strip_suffix("/*").unwrap_or(&canon).to_string();
                if absolute_path == "/" && !inc_prefix.is_empty() {
                    return Ok(true);
                }
                if !absolute_path.is_empty()
                    && inc_prefix.starts_with(&format!("{}/", absolute_path))
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn describe(&self) -> String {
        format!(
            "cap-token({} grants, grantee={})",
            self.cap.grants.len(),
            // Render grantee as a short hash hex prefix for logs.
            &super::hex_encode(&self.cap.grantee.to_bytes())[..16],
        )
    }
}

/// Does this grant entry include `system/tree` in handlers and `get`
/// in operations? (`*` matches.) Cheap predicate; used to skip
/// non-relevant grants when deriving content namespaces.
fn grant_allows_tree_get(grant: &entity_capability::GrantEntry) -> bool {
    let handler_ok = grant.handlers.include.iter().any(|h| h == "*" || h == "system/tree")
        && !grant
            .handlers
            .exclude
            .iter()
            .any(|h| h == "system/tree" || h == "*");
    let op_ok = grant.operations.include.iter().any(|o| o == "*" || o == "get")
        && !grant.operations.exclude.iter().any(|o| o == "get" || o == "*");
    handler_ok && op_ok
}

// ===========================================================================
// ClosureScope — closure-of-signed-root (NETWORK §6.5.6 Amendment 10)
// ===========================================================================

/// Serving scope for a publisher that advertises `signed_pointer`
/// (PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE). Amendment 10 (NETWORK §6.5.6):
/// when a signed root is published, the served set MUST cover the **transitive
/// trie-node closure reachable from `published-root.root_hash`** — the root
/// node, every interior sub-node, every leaf-bound value, plus the
/// `published-root` entity itself and its authenticating signature.
///
/// Why this is the floor and namespace-scope is not: CHAMP trie interior nodes
/// are hash-linked, not path-bound (V7 §1.7). A `NamespaceScope` only serves
/// hashes bound under a content path, so `CONTENT_GET(root_hash)` 404s and a
/// consumer's §1.1 walk-from-signed-root halts before the first node. This
/// predicate derives its membership from the live published-root head, so it
/// tracks the publisher automatically with no operator-maintained cap set.
///
/// **Content-face** (`in_scope`): hash ∈ {head, signature, trie-closure}.
/// **Tree-face** (`in_scope_path`): a path is served iff the host's binding at
/// that path resolves to a closure hash — which is exactly the signature
/// invariant-pointer leaf (`system/signature/{hex(head)}`, the surface the
/// outbound dialer resolves per V7 §5.2) and the published tree's path
/// bindings. The consumer re-verifies every fetched body by hash regardless
/// (§1.1), so a host binding an extra path to a closure hash gains nothing.
///
/// Membership is memoized and keyed by the head hash, so the trie is re-walked
/// only when the publisher advances the head.
pub struct ClosureScope {
    cache: Mutex<Option<ClosureSnapshot>>,
}

struct ClosureSnapshot {
    head: Hash,
    members: HashSet<Hash>,
}

impl ClosureScope {
    /// A closure scope tracking this listener's published-root head.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(None),
        }
    }

    /// Bring `self.cache` into agreement with the current published-root head.
    /// Cheap when the head is unchanged (one LocationIndex lookup + a compare);
    /// re-walks the trie only on head advance. Clears the cache when nothing is
    /// published (the route then serves nothing — identical 404, T4).
    fn refresh(&self, shared: &Arc<PeerShared>) {
        let peer_id = shared.peer_id.as_str();
        let head = shared
            .location_index
            .get(&crate::published_root::published_root_head_path(peer_id));
        let mut cache = self.cache.lock().unwrap();
        let head = match head {
            Some(h) => h,
            None => {
                *cache = None;
                return;
            }
        };
        if cache.as_ref().map(|s| s.head) == Some(head) {
            return;
        }
        let mut members = HashSet::new();
        members.insert(head); // the published-root entity itself
        if let Some(entity) = shared.content_store.get(&head) {
            if let Ok(data) = entity_types::PublishedRootData::from_entity(&entity) {
                members.extend(entity_tree::trie::collect_node_closure(
                    shared.content_store.as_ref(),
                    data.root_hash,
                ));
            }
        }
        // The authenticating signature, carried at the §5.2 invariant pointer.
        if let Some(sig_hash) = shared
            .location_index
            .get(&entity_hash::invariant_signature_path(peer_id, &head))
        {
            members.insert(sig_hash);
        }
        *cache = Some(ClosureSnapshot { head, members });
    }
}

impl Default for ClosureScope {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScopePredicate for ClosureScope {
    async fn in_scope(
        &self,
        hash: &Hash,
        shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        self.refresh(shared);
        let cache = self.cache.lock().unwrap();
        Ok(cache
            .as_ref()
            .map(|s| s.members.contains(hash))
            .unwrap_or(false))
    }

    async fn in_scope_path(
        &self,
        absolute_path: &str,
        shared: &Arc<PeerShared>,
    ) -> Result<bool, ScopeError> {
        self.refresh(shared);
        let bound = shared.location_index.get(absolute_path);
        let cache = self.cache.lock().unwrap();
        let members = match cache.as_ref() {
            Some(s) => &s.members,
            None => return Ok(false),
        };
        Ok(bound.map(|h| members.contains(&h)).unwrap_or(false))
    }

    fn describe(&self) -> String {
        "closure-of-signed-root".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_scope_trims_slashes() {
        assert_eq!(
            NamespaceScope::new("system/content/public").namespace(),
            "system/content/public"
        );
        assert_eq!(
            NamespaceScope::new("/system/content/public/").namespace(),
            "system/content/public"
        );
    }
}
