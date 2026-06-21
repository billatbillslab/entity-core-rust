//! Substitute-source miss-hook contract.
//!
//! CONTENT v3.7 amendment 4 (per `PROPOSAL-CONTENT-SUBSTITUTE-SOURCES.md`
//! §6). When [`EXTENSION-CONTENT-SUBSTITUTE-SOURCES`] is installed,
//! `system/content:get` on local miss + pending-clear MUST invoke a
//! substitute-consultation hook before contributing the hash to the
//! response's `missing` list.
//!
//! The trait lives in CONTENT so the dep direction stays correct —
//! substitute-sources depends on CONTENT (composes with it), not the
//! reverse. Installations without the substrate extension simply leave
//! the hook field `None`; `handle_get` behaves identically to today.
//!
//! **Cap-axis (per the named-capability-mapping ruling).** The
//! `content-substitute-consult` cap maps to a standard V7 §5.2 grant
//! check on `(handler="system/substitute/sources", operation="consult",
//! resource=target_namespace)`. The substrate owns the check — CONTENT
//! passes through the caller's `caller_capability` + `resource_target`
//! and the substrate runs `check_permission`. **Fail closed:** no
//! grant → deny; no `caller_capability` → deny. (Prior `bool`-based
//! signature relied on a permissive `is_some()` shortcut — that was
//! the cap-axis bug the ruling closes.)
//!
//! [EXTENSION-CONTENT-SUBSTITUTE-SOURCES]:
//!     ../../entity-content-substitute-sources/index.html

use async_trait::async_trait;
use entity_capability::{CapabilityToken, ResourceTarget};
use entity_entity::Entity;
use entity_handler::ExecuteFn;
use entity_hash::Hash;

/// Per-hash outcome from the substitute chain.
///
/// CONTENT's batch `get` treats every variant other than [`Resolved`]
/// as "still missing on this batch" — the requester retries the
/// missing-tail per the existing CONTENT contract. The single-hash
/// 503-vs-404 distinction from `PROPOSAL-CONTENT-SUBSTITUTE-SOURCES.md`
/// §3-RES.1 is deferred until v1.1 of this hook surface.
#[derive(Debug)]
pub enum MissOutcome {
    /// The chain produced a verified entity for the requested hash.
    /// The handler MUST include it in the response envelope; v1 does
    /// NOT auto-ingest into the local content store (consumer can call
    /// `system/content:ingest` to land the bytes long-term).
    Resolved(Entity),
    /// The chain was consulted but produced no hit, OR was not consulted
    /// (no chain, missing claimed source, cap denied, etc.). The hash
    /// stays in the response's `missing` list.
    NotResolved,
}

/// Hook installed on [`crate::SystemContentHandler`] to consult an
/// upstream substitute source on local-store miss.
///
/// Implemented by [`entity-content-substitute-sources`]'s
/// `ChainConsultHook` when the substrate extension is wired in.
#[async_trait]
pub trait MissResolver: Send + Sync {
    /// Try to resolve a single missing hash.
    ///
    /// - `claimed_source_peer_id` is the identity the consumer's
    ///   query carries (typically from the requesting entity's
    ///   `refs.author`). Bare-hash queries pass `None`; the substrate
    ///   short-circuits to `NotResolved` per §3-RES.2.
    /// - `caller_capability` is `ctx.caller_capability`. The substrate
    ///   runs `check_permission` against the per-ruling
    ///   `(system/substitute/sources, consult, resource_target)`
    ///   grant; absent or non-matching → deny (fail-closed).
    /// - `resource_target` is the consumer's resource scope on the
    ///   originating `system/content:get` — flows through as the
    ///   `resource` axis of the consult check.
    /// - `execute_fn` is the parent dispatch closure the substrate
    ///   uses to invoke `system/substitute/<type>:try`.
    async fn resolve_miss(
        &self,
        hash: &Hash,
        claimed_source_peer_id: Option<&Hash>,
        caller_capability: Option<&CapabilityToken>,
        resource_target: Option<&ResourceTarget>,
        execute_fn: &ExecuteFn,
    ) -> MissOutcome;
}
