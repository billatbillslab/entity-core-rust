//! `SelectionSink` — optional construction-time hook for verbs that
//! publish a Selection.
//!
//! Per `GUIDE-SHELL-FRAMING.md` §3.5 + §7.3: the shell is one
//! producer in the panel-source substrate. When the embedding wires a
//! sink, `cd`'s post-navigation Selection is published through it
//! (egui writes both the per-panel and app-aggregate slots so other
//! windows co-orient). When `None`, navigation happens but no publish
//! — standalone REPL and Godot palette can opt out.
//!
//! The crate doesn't know about window ids, app namespaces, or slot
//! paths — those are embedding concerns the sink encapsulates. The
//! crate just hands over the path that became current.

/// Embedding-supplied hook for publishing Selection updates.
///
/// The sink owns peer/window/slot routing. The crate calls `publish`
/// with the new path; the embedding decides where it lands.
pub trait SelectionSink {
    /// Publish `path` as the current selection. Called by verbs after
    /// they've successfully mutated `Shell::wd` (or any other producer
    /// state a future verb adds).
    fn publish(&self, path: &str);
}
