//! Pluggable signer-resolution registry (EXTENSION-QUORUM v1.1 §5).
//!
//! `concrete` mode is built-in (each `signers` entry is a peer-identity
//! hash). Other modes (e.g., `identity-resolved`) are registered by
//! consumer extensions at runtime via `register_resolver`.
//!
//! Resolvers MUST be deterministic and side-effect-free (§5.2).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

/// Per spec v1.1 IDENTITY-2 — default resolver recursion bound.
pub const MAX_RESOLVER_DEPTH: usize = 8;

/// Error returned by a resolver. Either resolution succeeded (returns a
/// peer hash), or one of the spec-defined fail-closed conditions.
#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum ResolverError {
    #[error("identity_resolver_unresolved: signer not findable in mode")]
    Unresolved,
    #[error("identity_resolver_max_depth_exceeded: depth>{0}")]
    MaxDepthExceeded(usize),
    #[error("identity_resolver_cycle: signer={0:?} re-visited")]
    Cycle(Hash),
}

/// Error returned by `ResolverRegistry::register`. PR-6
/// (PROPOSAL-SYSTEM-PEER-RENAME §PR-6): pinning fail-closed semantics —
/// re-registering a `mode_name` with a DIFFERENT handler MUST be rejected
/// (no silent replacement, no override, no stacking). Re-registering the
/// SAME handler (Arc::ptr_eq) is permitted as a no-op for hot-reload.
#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum RegisterError {
    #[error("resolver_already_registered: mode_name '{0}' has a different resolver registered")]
    AlreadyRegistered(String),
}

/// Context passed to resolver functions. Carries the substrate stores
/// plus per-invocation resolution state (depth + visited set) for
/// cycle/depth bound enforcement, plus the optional `as_of` timestamp
/// for historical resolution (SI-16).
pub struct ResolverContext<'a> {
    pub content_store: &'a Arc<dyn ContentStore>,
    pub location_index: &'a Arc<dyn LocationIndex>,
    pub as_of: Option<u64>,
    /// Per-invocation depth counter. Increments on each resolver call;
    /// resolvers that recursively trigger other resolutions (e.g., via
    /// nested `current_signer_set` calls) MUST inherit and propagate.
    pub depth: usize,
    /// Visited identity references for cycle detection. Populated by the
    /// orchestration layer; resolvers MAY check against it before
    /// recursing.
    pub visited: &'a mut HashSet<Hash>,
}

impl<'a> ResolverContext<'a> {
    /// Check the depth bound + cycle state against `next_ref`. Returns
    /// `Ok(())` if it's safe to recurse; `Err(...)` otherwise. Callers
    /// invoke this before nested resolution.
    pub fn enter(&mut self, next_ref: Hash) -> Result<(), ResolverError> {
        if self.depth >= MAX_RESOLVER_DEPTH {
            return Err(ResolverError::MaxDepthExceeded(MAX_RESOLVER_DEPTH));
        }
        if !self.visited.insert(next_ref) {
            return Err(ResolverError::Cycle(next_ref));
        }
        self.depth += 1;
        Ok(())
    }
}

/// Signature of a resolver function. Given a raw `signers[i]` hash from
/// the quorum entity, returns the resolved peer-identity hash (which the
/// K-of-N validator looks up signatures for) or a `ResolverError`.
///
/// Per v1.1 §5.2 + IDENTITY-2: resolver MUST be deterministic and
/// side-effect-free. Resolvers MAY recursively invoke `current_signer_set`
/// (via captured registry references), in which case they MUST propagate
/// `ResolverContext.depth` and `visited` state.
pub type ResolverFn = Arc<
    dyn Fn(&Hash, &mut ResolverContext) -> Result<Hash, ResolverError>
        + Send
        + Sync,
>;

/// Process-wide resolver registry. Identity (and other consumers) call
/// `register_resolver("identity-resolved", ...)` at install time.
#[derive(Default, Clone)]
pub struct ResolverRegistry {
    inner: Arc<RwLock<HashMap<String, ResolverFn>>>,
}

impl ResolverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a resolver for `mode_name`. PR-6
    /// (PROPOSAL-SYSTEM-PEER-RENAME §PR-6): MUST return
    /// `RegisterError::AlreadyRegistered` if `mode_name` is registered to
    /// a DIFFERENT handler. Re-registration of the SAME handler (Arc
    /// pointer-equal) is permitted as a no-op for hot-reload scenarios.
    /// No silent replacement; no stacking. Replacement requires explicit
    /// unregistration first (no `unregister_resolver` op in v2).
    pub fn register(
        &self,
        mode_name: &str,
        resolver: ResolverFn,
    ) -> Result<(), RegisterError> {
        let mut inner = self.inner.write().unwrap();
        if let Some(existing) = inner.get(mode_name) {
            if Arc::ptr_eq(existing, &resolver) {
                return Ok(());
            }
            return Err(RegisterError::AlreadyRegistered(mode_name.to_string()));
        }
        inner.insert(mode_name.to_string(), resolver);
        Ok(())
    }

    pub fn lookup(&self, mode_name: &str) -> Option<ResolverFn> {
        self.inner.read().unwrap().get(mode_name).cloned()
    }

    /// All currently-registered mode names plus `"concrete"` (built-in).
    /// Used in `quorum_resolver_unavailable` error envelopes (§5.3.1).
    pub fn available_modes(&self) -> Vec<String> {
        let mut modes = vec![crate::RESOLUTION_CONCRETE.to_string()];
        let inner = self.inner.read().unwrap();
        for k in inner.keys() {
            if k != crate::RESOLUTION_CONCRETE {
                modes.push(k.clone());
            }
        }
        modes.sort();
        modes
    }
}
