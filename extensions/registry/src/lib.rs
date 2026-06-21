//! EXTENSION-REGISTRY v1.0 — name-resolution substrate + local-name backend.
//!
//! A registry indirects from human-shareable names to cryptographic peer
//! identities + dial-able endpoints: `name → (peer_id, transports, ...)`.
//! This crate ships:
//!
//! - the **substrate**: the `system/registry` meta-resolver handler
//!   (`:resolve` / `:invalidate-cache`) with pin precedence, name-format
//!   dispatch, priority-ordered chain walk, signature/revocation validation,
//!   fail-closed chain exhaustion, and the SHOULD resolution-log (§2–§5, §11);
//! - the **local-name backend** (§6): the `system/registry/local-name` handler
//!   (`:bind` / `:unbind` / `:list` / `:update-transports`) with two-layer
//!   storage, NFC + name-path safety, and supersedes-chain audit.
//!
//! Local-name is the v1 concrete backend; other backends (peer-issued, did-web,
//! dns-txt, …) compose on the substrate in their own proposals. v1's
//! meta-resolver consults the local local-name store for `local-name` chain entries
//! and skips-with-warning any backend kind it does not implement (§4.2).
//!
//! Spec: `../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/extensions/network-peer-extensions/EXTENSION-REGISTRY.md`

pub mod data;
pub mod log;
pub mod local_name;
pub mod peer_issued;
pub mod registration;
pub mod resolver;
pub(crate) mod result;

#[cfg(test)]
mod tests;

pub use data::{
    normalize_name, validate_name_safety, BindingData, DispatchRule, IssuerPolicyData,
    LocalNameConfigData, PinnedBinding, RegisterRequestData, ResolutionLogData, ResolutionResult,
    ResolverChainEntry, ResolverConfigData, RevocationData,
};
pub use log::ResolutionLog;
pub use local_name::LocalNameHandler;
pub use peer_issued::resolve_one as peer_issued_resolve_one;
pub use registration::RegisterRequestHandler;
pub use resolver::RegistryHandler;

use entity_hash::Hash;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Capability surface (§5)
// ---------------------------------------------------------------------------

pub const CAP_REGISTRY_RESOLVE: &str = "system/capability/registry-resolve";
pub const CAP_REGISTRY_CONFIGURE: &str = "system/capability/registry-configure";
pub const CAP_REGISTRY_PIN: &str = "system/capability/registry-pin";
pub const CAP_REGISTRY_CACHE_CONTROL: &str = "system/capability/registry-cache-control";
pub const CAP_REGISTRY_LOCAL_NAME_BIND: &str = "system/capability/registry-local-name-bind";
pub const CAP_REGISTRY_LOCAL_NAME_UNBIND: &str = "system/capability/registry-local-name-unbind";
pub const CAP_REGISTRY_LOCAL_NAME_LIST: &str = "system/capability/registry-local-name-list";

// Peer-issued live-registration caps (§6a.9.1). Deliberately NOT in
// REGISTRY_SEED_CAPS: `registry-request-binding` is the *external* publisher
// surface (an operator grants it explicitly — broadly for `open`, narrowly for
// `allowlist`), and `registry-issue-binding` is the internal sign+publish act
// the policy logic holds. The local operator reaches its own ops through the
// §6.9a owner-self-grant, so auto-seeding these would only widen the attack
// surface for no local benefit.
pub const CAP_REGISTRY_REQUEST_BINDING: &str = "system/capability/registry-request-binding";
pub const CAP_REGISTRY_ISSUE_BINDING: &str = "system/capability/registry-issue-binding";
pub const CAP_REGISTRY_MANAGE_ISSUER_POLICY: &str =
    "system/capability/registry-manage-issuer-policy";

/// The seven caps the seed-policy grants the local peer on first install
/// (§5.2 / absorption §6.11 — otherwise the user cannot use their own local-name
/// store or run resolutions).
pub const REGISTRY_SEED_CAPS: &[&str] = &[
    CAP_REGISTRY_RESOLVE,
    CAP_REGISTRY_CONFIGURE,
    CAP_REGISTRY_PIN,
    CAP_REGISTRY_CACHE_CONTROL,
    CAP_REGISTRY_LOCAL_NAME_BIND,
    CAP_REGISTRY_LOCAL_NAME_UNBIND,
    CAP_REGISTRY_LOCAL_NAME_LIST,
];

// Backend-kind discriminators (resolver-config.backend_kind).
pub const BACKEND_KIND_LOCAL_NAME: &str = "local-name";
/// Peer-issued backend (PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND). Reads + verifies
/// a remote registry's signed bindings against a pinned registry key.
pub const BACKEND_KIND_PEER_ISSUED: &str = "peer-issued";

/// Wire entity type for the `:resolve` return payload (§2.1 erratum
/// / Ruling-3). The `ResolutionResult` fields are carried **flat** under `data`;
/// MUST NOT be wrapped under `system/protocol/status` or any other envelope.
pub const TYPE_REGISTRY_RESOLUTION_RESULT: &str = "system/registry/resolution-result";

// ---------------------------------------------------------------------------
// Storage paths (§3 universal binding body + §6.3 local-name two-layer)
// ---------------------------------------------------------------------------

/// Universal binding-body path: `/{peer}/system/registry/binding/{hex}` (§3).
pub fn binding_body_path(peer_id: &str, hash: &Hash) -> String {
    format!("/{}/system/registry/binding/{}", peer_id, hash.to_hex())
}

/// Local-name tree-pointer path: `/{peer}/system/registry/binding/local-name/{name}`
/// holding the bare hash of the current head binding body (§6.3). `name` is the
/// normalized form.
pub fn local_name_pointer_path(peer_id: &str, normalized_name: &str) -> String {
    format!(
        "/{}/system/registry/binding/local-name/{}",
        peer_id, normalized_name
    )
}

/// Prefix for enumerating local-name pointers (the live name→hash index, §6.5).
pub fn local_name_pointer_prefix(peer_id: &str) -> String {
    format!("/{}/system/registry/binding/local-name/", peer_id)
}

/// Peer-issued by-name tree-pointer path
/// `/{registry}/system/registry/binding/by-name/{name}` holding the bare hash of
/// the current binding body (PROPOSAL-PEER-ISSUED §2.2). Direct analog of the
/// local-name pointer, different prefix (`by-name/`). `peer_id` here is the
/// **registry's** peer-id (the binding lives in the registry peer's tree), and
/// `name` is the NFC-normalized form.
pub fn by_name_pointer_path(registry_peer_id: &str, normalized_name: &str) -> String {
    format!(
        "/{}/system/registry/binding/by-name/{}",
        registry_peer_id, normalized_name
    )
}

/// Prefix for enumerating a registry's by-name pointers (PROPOSAL-PEER-ISSUED §2.2).
pub fn by_name_pointer_prefix(registry_peer_id: &str) -> String {
    format!("/{}/system/registry/binding/by-name/", registry_peer_id)
}

/// Invariant-pointer path for a binding's authenticating signature
/// `/{registry}/system/signature/{hex(binding_hash)}` (V7 §5.2 / §989).
pub fn signature_pointer_path(registry_peer_id: &str, binding_hash: &Hash) -> String {
    format!(
        "/{}/system/signature/{}",
        registry_peer_id,
        binding_hash.to_hex()
    )
}

/// Prefix for a registry's revocation subtree (§3.1).
pub fn revocation_prefix(registry_peer_id: &str) -> String {
    format!("/{}/system/registry/revocation/", registry_peer_id)
}

/// By-target revocation index `/{registry}/system/registry/revocation/by-target/{hex}`
/// → the revocation entity (§6a.6 — the O(1) revocation analog of the §6a.3
/// by-name index). Written by `:revoke-request` alongside the own-hash-keyed
/// pointer the resolve-side scan reads.
pub fn revocation_by_target_path(registry_peer_id: &str, binding_hash: &Hash) -> String {
    format!(
        "/{}/system/registry/revocation/by-target/{}",
        registry_peer_id,
        binding_hash.to_hex()
    )
}

/// Registry-local issuer-policy entity path (§6a.9.1).
pub fn issuer_policy_path(peer_id: &str) -> String {
    format!("/{}/system/registry/issuer-policy", peer_id)
}

/// Per-requester seen-nonce marker `/{registry}/system/registry/register-nonce/{requester}/{hex}`
/// (§6a.9 replay defense). Presence = the nonce was already consumed.
pub fn register_nonce_path(registry_peer_id: &str, requester_peer_id: &str, nonce: &[u8]) -> String {
    format!(
        "/{}/system/registry/register-nonce/{}/{}",
        registry_peer_id,
        requester_peer_id,
        hex_lower(nonce)
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn resolver_config_path(peer_id: &str) -> String {
    format!("/{}/system/registry/resolver-config", peer_id)
}

pub fn local_name_config_path(peer_id: &str) -> String {
    format!("/{}/system/registry/local-name-config", peer_id)
}

pub fn resolution_log_path(peer_id: &str, seq: u64) -> String {
    format!("/{}/system/registry/resolution-log/{}", peer_id, seq)
}

pub fn resolution_log_prefix(peer_id: &str) -> String {
    format!("/{}/system/registry/resolution-log/", peer_id)
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("registry entity decode failed: {0}")]
    Decode(String),
    #[error("registry entity encode failed: {0}")]
    Encode(String),
    #[error("invalid registry request: {0}")]
    Invalid(String),
}
