//! DOMAIN-LOCAL-FILES v1.2 — `local/files` handler over EXTENSION-CONTENT v3.5.
//!
//! Spec: `../entity-core-architecture/.../core-protocol-domain/specs/domains/DOMAIN-LOCAL-FILES.md`.
//!
//! Maps a host filesystem subtree into the entity tree. File bytes are
//! chunked via FastCDC + persisted through the CONTENT v3.5 substrate
//! (`system/content/blob` + `system/content/chunk`); file entities carry
//! a `system/hash` reference into the content store. Cross-handler
//! dedup is structural — the same bytes through any handler produce
//! the same blob and chunks.
//!
//! Surfaces:
//! - [`LocalFilesHandler`] — the `local/files` handler, registered at
//!   peer build via `core/peer`.
//! - [`reverse::start_reverse_write`] — wires the tree-change subscription
//!   for §5 reverse write (tree → filesystem).
//! - Type and config helpers in [`types`] and [`config`].
//!
//! Native-only: this crate uses `std::fs` and `notify`. WASM builds skip
//! the `local-files` feature in `core/peer`.

#![cfg(not(target_arch = "wasm32"))]

pub mod atomic;
pub mod config;
pub mod domain_types;
pub mod handler;
pub mod operations;
pub mod reverse;
pub mod stat_cache;
pub mod types;
pub mod watcher;

pub use domain_types::all_domain_types;
pub use stat_cache::StatCache;

pub use config::{file_skipped, matches_exclude, matches_include, resolve_fs_path, RootMapping};
pub use handler::{LocalFilesHandler, HANDLER_PATTERN};
pub use reverse::start_reverse_write;
pub use types::{
    DeletedData, DirectoryData, DirectoryEntryData, FileData, RootConfigData, WatchRequestData,
    WatcherConfigData, WriteRequestData, TYPE_DELETED, TYPE_DIRECTORY, TYPE_DIRECTORY_ENTRY,
    TYPE_FILE, TYPE_ROOT_CONFIG, TYPE_WATCH_REQUEST, TYPE_WATCHER_CONFIG, TYPE_WRITE_REQUEST,
};
