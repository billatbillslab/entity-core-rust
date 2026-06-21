//! Entity Core Protocol — facade crate.
//!
//! Re-exports the public API from all internal crates.
//! External consumers should depend on this crate only.

pub use entity_ecf as ecf;
pub use entity_hash as hash;
pub use entity_entity as entity;
pub use entity_crypto as crypto;
pub use entity_store as store;
pub use entity_types as types;
pub use entity_capability as capability;
pub use entity_wire as wire;
pub use entity_handler as handler;
pub use entity_protocol as protocol;
pub use entity_tree as tree;
pub use entity_peer as peer;
