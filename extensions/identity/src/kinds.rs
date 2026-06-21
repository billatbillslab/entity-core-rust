//! Identity-context kinds, functions, and modes
//! (EXTENSION-IDENTITY v3.2 §3.3, §4.2, §4.2a).

use crate::IdentityError;

/// Identity-owned `properties.kind` values (per §3.3 / kind table §4.1).
/// All are namespaced with `identity-` to avoid cross-extension collisions.
pub const KIND_IDENTITY_CERT: &str = "identity-cert";
pub const KIND_IDENTITY_ROTATION_HANDOFF: &str = "identity-rotation-handoff";
pub const KIND_IDENTITY_ROTATION_RECOVERY: &str = "identity-rotation-recovery";
pub const KIND_IDENTITY_RETIREMENT: &str = "identity-retirement";

/// Set of identity-context lifecycle kinds (§3.6 `identity_lifecycle_kinds`).
/// Used by `identity_verify_cert`'s structural-validation gate.
pub fn identity_lifecycle_kinds() -> &'static [&'static str] {
    &[
        KIND_IDENTITY_ROTATION_HANDOFF,
        KIND_IDENTITY_ROTATION_RECOVERY,
        KIND_IDENTITY_RETIREMENT,
    ]
}

/// Standard cert function values (per §4.2). App-defined values are
/// accepted via the "any string" fallback in topology dispatch; this
/// list is for structural validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Function {
    Controller,
    Agent,
    Identifier,
}

impl Function {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Agent => "agent",
            Self::Identifier => "identifier",
        }
    }

    /// Parse a function string. Returns `Ok(Some(_))` for standard
    /// functions, `Ok(None)` for app-defined (treated per §4.2 row 5),
    /// or `Err` if the value is non-string-typed.
    pub fn parse_optional(s: &str) -> Option<Self> {
        match s {
            "controller" => Some(Self::Controller),
            "agent" => Some(Self::Agent),
            "identifier" => Some(Self::Identifier),
            _ => None,
        }
    }
}

/// `valid_functions()` per §3.6 — the standard cert function set used
/// by the structural-validation reject-on-unknown check.
pub fn valid_functions() -> &'static [&'static str] {
    &["controller", "agent", "identifier"]
}

/// Publication mode for cert audience tier (§4.2a). REQUIRED on all
/// `identity-cert` attestations per §4.2 (eliminates the in-flight
/// rotation race v3.0/v2.2 had).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Internal,
    Public,
    PerRelationship,
    Embedded,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Public => "public",
            Self::PerRelationship => "per-relationship",
            Self::Embedded => "embedded",
        }
    }

    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        match s {
            "internal" => Ok(Self::Internal),
            "public" => Ok(Self::Public),
            "per-relationship" => Ok(Self::PerRelationship),
            "embedded" => Ok(Self::Embedded),
            other => Err(IdentityError::InvalidParam(format!("unknown mode: {}", other))),
        }
    }
}

/// Per-function valid modes (per §4.2 normative table). Returns `true`
/// if the (function, mode, sub_controller?) combination is allowed.
///
/// `sub_controller` flag matters only for `Controller`: top-level
/// controllers may use `public` or `internal`; sub-controllers MUST be
/// `internal` only.
pub fn is_valid_mode_for_function(
    function: Option<Function>,
    mode: Mode,
    sub_controller: bool,
) -> bool {
    match function {
        Some(Function::Controller) => {
            if sub_controller {
                matches!(mode, Mode::Internal)
            } else {
                matches!(mode, Mode::Public | Mode::Internal)
            }
        }
        Some(Function::Agent) => true, // any of the four
        Some(Function::Identifier) => matches!(mode, Mode::Internal),
        None => true, // app-defined; per §4.2 row 5 default is internal
    }
}

/// PI-11 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-11): valid modes per
/// function, expressed as a string array for use in `400
/// invalid_mode_for_function` error envelopes. `sub_controller=true`
/// narrows Controller's set to `["internal"]`.
pub fn valid_modes_for_function(
    function: Option<Function>,
    sub_controller: bool,
) -> &'static [&'static str] {
    match function {
        Some(Function::Controller) => {
            if sub_controller {
                &["internal"]
            } else {
                &["internal", "public"]
            }
        }
        Some(Function::Agent) => &["internal", "public", "per-relationship", "embedded"],
        Some(Function::Identifier) => &["internal"],
        None => &["internal", "public", "per-relationship", "embedded"],
    }
}
