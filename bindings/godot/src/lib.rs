//! Godot GDExtension bindings for Entity Core Protocol.
//!
//! Provides GDExtension classes for Godot 4:
//! - `EntityPeer` (Node) — peer lifecycle tied to scene tree
//! - `EntityCbor` (RefCounted) — CBOR diagnostic utility
//! - `EntityData` (Resource) — entity type + data + hash wrapper
//! - `EntitySubscription` (RefCounted) — path-prefix change-event handle
//! - `EntityShell` (RefCounted) — `entity-shell` crate wrapper (pwd, cd)

mod bootstrap_ops;
mod cbor_util;
mod compute_ops;
mod entity_resource;
mod entity_subscription;
mod peer_manager_node;
mod peer_node;
mod peer_op_future;
#[cfg(not(target_arch = "wasm32"))]
mod persistence;
mod shell_node;

use godot::prelude::*;

struct EntityCoreExtension;

#[gdextension]
unsafe impl ExtensionLibrary for EntityCoreExtension {}
