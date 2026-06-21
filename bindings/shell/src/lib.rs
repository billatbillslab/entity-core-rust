//! `entity-shell` — cross-frontend verb dispatcher for the entity-core shell.
//!
//! The crate is consumed by:
//! - `egui-entity-core-rust` (DOM window adapter — primary consumer)
//! - `godot-entity-core-rust` (palette + window adapters)
//! - `entity-core-rust/cmd/entity-shell` (standalone REPL binary —
//!   forcing function for crate shape; Phase 5 of the shell-extraction
//!   plan)
//!
//! Builds against `GUIDE-SHELL-FRAMING.md` §3.3 (verb-result variant
//! set) and §3.7 (verbs are pure functions of `(Shell, args, ...) →
//! Result<VerbOutput, ShellError>`).
//!
//! Phase 3a-cd: `pwd` + `cd` lifted; `PeerBinding` + `SelectionSink`
//! traits materialized against `cd`'s concrete needs (alias expansion
//! + post-navigation publish). Subsequent verb lifts grow the
//! `PeerBinding` surface (tree ops, dispatch, async query) without
//! revisiting the trait boundary's shape.

pub mod action;
pub mod alias;
pub mod binding;
pub mod dispatcher;
pub mod display;
pub mod format;
pub mod path;
pub mod result;
pub mod runtime;
pub mod shell;
pub mod sink;
pub mod verbs;

pub use action::{AppActionSink, PeerMode, ShellRequest, TailInfo};
pub use binding::{EntityRead, PeerBinding, QueryMatch, QueryResults, TreeListingEntry};
pub use result::{
    DispatchChunk, EntityView, ErrorCode, InfoRow, ListingSection, ShellError, StreamChunk,
    TreeEntry, TreeView, VerbOutput,
};
pub use shell::Shell;
pub use sink::SelectionSink;
