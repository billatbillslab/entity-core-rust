//! `open [<window>] [@peer]` — spawn a window via the embedding.
//!
//! Tier A per guide §4.3 — application-derived. The window-type
//! catalog lives with the embedding (via `AppActionSink::available_windows`
//! / `resolve_window_name`); the verb resolves the name and submits a
//! `SpawnWindow` request. Bare `open` returns the catalog as a Listing
//! so users can discover what's available.
//!
//! Factored per guide §8.1 four-layer model: `open_op` is the typed
//! verb-op (takes pre-resolved window type-name + peer-id); `open` is
//! the verb-parser. The optional `@peer` arg (per §6.2 standalone-
//! alias) is resolved via `alias::resolve_pid` in the verb-parser.
//!
//! **Friction note (§8.1 dispatcher-tier resolution):** the optional
//! `@peer` arg is at a dynamic position — the LAST positional, after
//! variable-length window-name parts. Static dispatcher metadata
//! can't express this without parametric dispatch (§5.2). Resolution
//! stays in the verb-parser here for now; identifier-form expansion
//! is centralized in `alias::resolve_pid` so the migration to
//! dispatcher tier (when parametric lands) is mechanical.

use crate::action::{AppActionSink, ShellRequest};
use crate::alias;
use crate::binding::PeerBinding;
use crate::display;
use crate::result::{InfoRow, ListingSection, ShellError, VerbOutput};

/// Verb-op (§8.1). Render the available-windows catalog as a Listing.
pub fn open_list_op(action_sink: &dyn AppActionSink) -> VerbOutput {
    let windows = action_sink.available_windows();
    if windows.is_empty() {
        return VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                "open: no window types registered by this embedding",
                Vec::new(),
            )],
        };
    }
    let rows: Vec<String> = windows.iter().map(|n| format!("  {}", n)).collect();
    VerbOutput::Listing {
        sections: vec![ListingSection::with_header(
            "open: available window types:",
            rows,
        )],
    }
}

/// Verb-op (§8.1). Submit a `SpawnWindow` request for an already-
/// resolved window `type_name` and `peer_id`.
pub fn open_op(
    action_sink: &dyn AppActionSink,
    type_name: String,
    peer_id: String,
) -> VerbOutput {
    let short = display::short_pid(&peer_id);
    let type_name_clone = type_name.clone();
    action_sink.submit(ShellRequest::SpawnWindow {
        type_name,
        peer_id: Some(peer_id),
    });
    VerbOutput::Info(vec![InfoRow::text(format!(
        "→ opening {} on {}",
        type_name_clone, short
    ))])
}

/// Verb-parser (§8.1).
///
/// `args` shape:
/// - `[]` → list available windows (from sink).
/// - `[<name-parts...>]` → spawn `name` on the bound peer.
/// - `[<name-parts...>, "@peer"]` → spawn `name` on `@peer`.
pub fn open(
    args: &[&str],
    binding: &dyn PeerBinding,
    action_sink: &dyn AppActionSink,
) -> Result<VerbOutput, ShellError> {
    if args.is_empty() {
        return Ok(open_list_op(action_sink));
    }

    let (peer_ref, name_args): (Option<&str>, &[&str]) = match args.last() {
        Some(last) if last.starts_with('@') => (Some(*last), &args[..args.len() - 1]),
        _ => (None, args),
    };
    if name_args.is_empty() {
        return Err(ShellError::usage(
            "open: missing window name (got only a peer ref)",
        ));
    }
    let joined = name_args.join(" ");
    let type_name = action_sink
        .resolve_window_name(&joined)
        .or_else(|| action_sink.resolve_window_name(name_args[0]))
        .ok_or_else(|| {
            let avail = action_sink.available_windows().join(", ");
            ShellError::not_found(format!(
                "open: unknown window '{}'. Try one of: {}",
                joined, avail
            ))
        })?;
    let peer_id = match peer_ref {
        Some(pref) => alias::resolve_pid(pref, binding)
            .map_err(|msg| ShellError::not_found(format!("open: {}", msg)))?,
        None => binding.peer_id().to_string(),
    };
    Ok(open_op(action_sink, type_name, peer_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};
    use std::cell::RefCell;

    struct StubBinding;
    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { "alice" }
        fn primary_peer_id(&self) -> String { "alice".into() }
        fn peer_ids(&self) -> Vec<String> { vec!["alice".into()] }
        fn connected_peers(&self) -> Vec<String> { Vec::new() }
        fn peer_label(&self, _pid: &str) -> Option<String> { None }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }
    }

    struct StubSink {
        windows: Vec<String>,
        requests: RefCell<Vec<ShellRequest>>,
    }

    impl AppActionSink for StubSink {
        fn submit(&self, request: ShellRequest) {
            self.requests.borrow_mut().push(request);
        }
        fn available_windows(&self) -> Vec<String> {
            self.windows.clone()
        }
    }

    fn sink() -> StubSink {
        StubSink {
            windows: vec!["Shell".into(), "Entity Tree".into(), "Settings".into()],
            requests: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn bare_open_lists_available_windows() {
        let s = sink();
        match open(&[], &StubBinding, &s).unwrap() {
            VerbOutput::Listing { sections } => {
                assert!(sections[0].header.as_ref().unwrap().contains("available"));
                assert_eq!(sections[0].entries.len(), 3);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn bare_open_with_empty_catalog_reports_none() {
        struct Empty;
        impl AppActionSink for Empty {
            fn submit(&self, _r: ShellRequest) {}
        }
        match open(&[], &StubBinding, &Empty).unwrap() {
            VerbOutput::Listing { sections } => {
                assert!(sections[0].header.as_ref().unwrap().contains("no window types"));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn spawns_window_with_resolved_name() {
        let s = sink();
        open(&["entity-tree"], &StubBinding, &s).unwrap();
        let req = s.requests.borrow()[0].clone();
        match req {
            ShellRequest::SpawnWindow { type_name, peer_id } => {
                assert_eq!(type_name, "Entity Tree");
                assert_eq!(peer_id.as_deref(), Some("alice"));
            }
            other => panic!("expected SpawnWindow, got {:?}", other),
        }
    }

    #[test]
    fn unknown_window_returns_not_found() {
        let s = sink();
        let err = open(&["nonexistent"], &StubBinding, &s).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::NotFound);
    }

    #[test]
    fn open_op_submits_with_resolved_inputs() {
        let s = sink();
        open_op(&s, "Settings".into(), "alice".into());
        let req = s.requests.borrow()[0].clone();
        match req {
            ShellRequest::SpawnWindow { type_name, peer_id } => {
                assert_eq!(type_name, "Settings");
                assert_eq!(peer_id.as_deref(), Some("alice"));
            }
            other => panic!("expected SpawnWindow, got {:?}", other),
        }
    }
}
