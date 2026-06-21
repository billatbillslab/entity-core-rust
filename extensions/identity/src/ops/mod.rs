//! `system/identity` per-op implementations.
//!
//! Each op (per EXTENSION-IDENTITY v3.2 §6) lives in its own submodule.
//! The Handler trait dispatch arms in `super` (the parent `handler` module)
//! call `self.handle_<op>(...)` which resolves to the impl block here via
//! Rust's cross-file `impl IdentityHandler { ... }`.

pub mod configure;
pub mod create_attestation;
pub mod create_quorum;
pub mod process_attestation;
pub mod publish_attestation;
pub mod revoke_attestation;
pub mod supersede_attestation;
