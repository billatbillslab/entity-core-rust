//! `system/role` handler — named grant bundles + context-scoped exclusion
//! (EXTENSION-ROLE v1.5).
//!
//! Roles are a management abstraction over the capability system: a named
//! set of grant entries that can be assigned to peers within a context.
//! Assignments derive capability tokens from the role definition;
//! exclusions deny a peer all role-derived access within a context.
//!
//! Spec: `../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/extensions/EXTENSION-ROLE.md`
//!
//! Open spec questions surfaced during implementation are tracked in
//! `docs/SPEC-AMBIGUITIES-ROLE.md`.

pub mod data;
pub mod handler;
pub mod helpers;
pub mod hook;
pub mod paths;
pub mod policy;
pub mod startup;

#[cfg(test)]
mod tests;

pub use data::{
    decode_grant_array_value, hex_segment, RoleAssignmentData, RoleData,
    RoleDerivedTokenLinkData, RoleExclusionData, RoleInitialGrantPolicyData,
    MODE_ANONYMOUS_ALLOW, MODE_ANONYMOUS_DENY, MODE_RECOGNIZE_ON_ATTESTATION,
    TYPE_ROLE, TYPE_ROLE_ASSIGNMENT, TYPE_ROLE_DERIVED_TOKEN_LINK,
    TYPE_ROLE_EXCLUSION, TYPE_ROLE_INITIAL_GRANT_POLICY,
};
pub use handler::RoleHandler;
pub use helpers::{is_excluded, resolve_grant_templates};
pub use hook::RoleExclusionSweepHook;
pub use policy::{
    build_policy_resolver, recognize_identity_cert, resolve_grants,
    PolicyResolverDeps, DEFAULT_MAX_CHAIN_DEPTH,
};
pub use startup::{
    startup_role_assignment, startup_role_definition, StartupAssignmentResult, StartupError,
};
pub use paths::{
    hash_from_peer_segment, parse_assignment_path, parse_exclusion_path,
    parse_role_definition_path, path_role_assignment, path_role_definition,
    path_role_derived_link, path_role_derived_token, path_role_exclusion,
    peer_segment_from_hash, prefix_role_assignment, prefix_role_assignment_peer,
    prefix_role_derived_links_peer, prefix_role_derived_peer, resolve_template_str,
    ParsedAssignmentPath, ParsedExclusionPath, ParsedRoleDefPath,
    PATH_INITIAL_GRANT_POLICY, RESERVED_ROLE_NAMES, ROLE_DERIVED_PREFIX, ROLE_PREFIX,
};

use thiserror::Error;

/// Op manifest names — used by the handler manifest and by `bootstrap_handler`
/// in the peer crate. Kept here so type-registration / wiring code can
/// reference them by symbol.
pub const OP_DEFINE: &str = "define";
pub const OP_ASSIGN: &str = "assign";
pub const OP_UNASSIGN: &str = "unassign";
pub const OP_EXCLUDE: &str = "exclude";
pub const OP_UNEXCLUDE: &str = "unexclude";
pub const OP_RE_DERIVE: &str = "re-derive";
pub const OP_DELEGATE: &str = "delegate";

/// All operations declared by `system/role` per §4.1 manifest.
pub const ALL_OPERATIONS: &[&str] = &[
    OP_DEFINE,
    OP_ASSIGN,
    OP_UNASSIGN,
    OP_EXCLUDE,
    OP_UNEXCLUDE,
    OP_RE_DERIVE,
    OP_DELEGATE,
];

/// Op-input / op-output type names (§4.2).
pub const TYPE_DEFINE_REQUEST: &str = "system/role/define-request";
pub const TYPE_DEFINE_RESULT: &str = "system/role/define-result";
pub const TYPE_ASSIGN_REQUEST: &str = "system/role/assign-request";
pub const TYPE_ASSIGN_RESULT: &str = "system/role/assign-result";
pub const TYPE_EXCLUDE_RESULT: &str = "system/role/exclude-result";
pub const TYPE_RE_DERIVE_REQUEST: &str = "system/role/re-derive-request";
pub const TYPE_RE_DERIVE_RESULT: &str = "system/role/re-derive-result";
pub const TYPE_DELEGATE_REQUEST: &str = "system/role/delegate-request";
pub const TYPE_DELEGATE_RESULT: &str = "system/role/delegate-result";

#[derive(Debug, Error)]
pub enum RoleError {
    #[error("decode error: {0}")]
    Decode(String),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("invalid params: {0}")]
    InvalidParam(String),
    #[error("malformed resource path: {0}")]
    MalformedResource(String),
    #[error("role not found: {0}")]
    RoleNotFound(String),
    #[error("assignee excluded in context: {context}")]
    AssigneeExcluded { context: String },
    /// RL2 fail-closed (§4.3 step 5, §5.1, §9.1, IA10): caller's authority
    /// does not cover the role's derived grant set.
    #[error("assigner authority insufficient for role {role}")]
    AssignerAuthorityInsufficient { role: String },
}
