//! EXTENSION-STORAGE-SUBSTITUTE-HTTP v1 — `http` convention.
//!
//! First concrete convention on the
//! [substitute-sources substrate](entity_storage_substitute_sources). Registers
//! a handler at `system/substitute/http` that implements the `try`
//! operation via **Mechanism A** (HTTP-as-storage-transport) — an
//! inline HTTP GET against the publisher's content URL prefix, with
//! hash-verification on the fetched bytes as the sole trust anchor.
//!
//! Per `GUIDE-EXTENSION-DEVELOPMENT.md §3.7` and the STORAGE-SUBSTITUTE-HTTP
//! proposal §1: **this is NOT BRIDGE-HTTP.** No `system/bridge/http:get`
//! invocation, no `system/capability/bridge-http-fetch` cap involved.
//! The bytes-on-wire ARE entity-encoded; the content hash carries trust.
//!
//! **Naming.** The storage-substitute cross-impl rulings
//! renamed `static-cdn` → `http`: this is just HTTP transport — we don't
//! know what's behind the origin (a bucket, nginx, `python3 -m http.server`
//! …). "static-cdn" was over-specific.
//!
//! Scope of this initial landing (v1.0):
//! - URL construction for the three content layouts (`flat`,
//!   `sharded-2-flat`, `sharded-2-4`).
//! - Bare-hash fetch (the §1 load-bearing baseline): URL → GET →
//!   `decode_entity` → return as handler result. The substrate hash-
//!   verifies (`Hash::compute(type, data) == requested_hash`) before
//!   handing the entity back to CONTENT.
//! - `tree_leaf_suffix` field parsed but NOT yet exercised — relevant
//!   only on the path-resolution (manifest) path which lands in v1.1.
//!
//! Deferred to v1.1 (cross-impl-agreed defer; Ruling 5):
//! - Manifest fetch + signature-verify + `seq` freshness + `predecessor`
//!   chain. All three impls land manifest processing together.
//! - Path-to-hash resolution via `path_index`.
//!
//! Deferred to Phase 2 (storage-tree-half):
//! - Tree-miss substitute (path → hash mutable signed-pointer fetch).
//!   Today the substrate hooks `content:get` (hash-verified); the
//!   tree-miss half (path→hash binding fetch, signature-verified,
//!   mutable) belongs in the Phase-2 transport-composition exploration.

#![cfg(not(target_arch = "wasm32"))]

mod handler;
mod url;

pub use handler::HttpSubstituteHandler;
pub use url::{ContentLayout, EndpointConfig, EndpointDecodeError, UrlBuildError};

/// Handler pattern this convention registers at.
///
/// The substrate's chain-consult algorithm dispatches against this
/// pattern when an entry's `substitute_type` is `"http"`.
pub const PATTERN_HTTP: &str = "system/substitute/http";

/// Convention discriminator written into substitute-source entries
/// (matches §2.1 of the proposal; renamed from `static-cdn` per the
/// cross-impl ruling).
pub const SUBSTITUTE_TYPE_HTTP: &str = "http";
