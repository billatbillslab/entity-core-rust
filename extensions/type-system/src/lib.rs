//! `system/type` + `system/type/constraint/*` handlers (EXTENSION-TYPE v1.1).
//!
//! This crate implements the type extension as defined in
//! `EXTENSION-TYPE.md` v1.1. Two handlers ship here:
//!
//! - [`StandardConstraintHandler`] — bound at pattern
//!   `system/type/constraint/*`, operation `validate`. Implements §5.4
//!   dispatch over the 11 standard constraint kinds.
//! - [`TypeHandler`] — bound at pattern `system/type`, operation `validate`
//!   (R-T3, in progress). §2.3 two-phase: structural validation then
//!   constraint dispatch.
//!
//! Resolution is Strategy 1 only (path-convention lookup) per v1.1 §1.5.

pub mod compare;
pub mod constraint;
pub mod format;
pub mod glob;
pub mod narrowing;
pub mod validate;

pub use constraint::StandardConstraintHandler;
pub use validate::TypeHandler;
