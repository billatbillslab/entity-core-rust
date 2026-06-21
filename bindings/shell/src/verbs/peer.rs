//! `peer [list|create|delete|rename]` — sub-op routing.
//!
//! `list` reads via `PeerBinding`; create/delete/rename submit
//! `ShellRequest` variants via `AppActionSink`. The lifecycle ops
//! return `Info` rows with the dispatched-state arrow (`"→ creating
//! ..."`) — the embedding handles the actual operation asynchronously.
//!
//! Factored per guide §8.1 four-layer model: each sub-op exposes a
//! verb-op (`peer_list_op`, `peer_create_op`, `peer_delete_op`,
//! `peer_rename_op`) taking already-resolved bare peer-ids; the verb-
//! parser `peer` does sub-op routing + arg-parsing + alias resolution
//! via `alias::resolve_pid` (identifier-form per §6.2).
//!
//! **Friction note (§8.1 dispatcher-tier resolution):** the
//! identifier-arg-position depends on the sub-op (none for `list` /
//! `create`, position 1 for `delete` / `rename`). Static dispatcher
//! metadata can't express this without parametric dispatch (§5.2). The
//! alias resolution stays in the verb-parser here for now; resolution
//! is centralized in `alias::resolve_pid` so the migration to dispatcher
//! tier (when parametric lands) is a near-mechanical move.

use crate::action::{AppActionSink, PeerMode, ShellRequest};
use crate::alias;
use crate::binding::PeerBinding;
use crate::display;
use crate::result::{InfoRow, ListingSection, ShellError, VerbOutput};

/// Verb-op (§8.1). Render the peer listing (local + remote sections).
pub fn peer_list_op(binding: &dyn PeerBinding) -> VerbOutput {
    let primary = binding.primary_peer_id();
    let local_ids = binding.peer_ids();
    let remotes = binding.connected_peers();

    let local_rows: Vec<String> = local_ids
        .iter()
        .map(|pid| {
            let short = display::short_pid(pid);
            let role = if pid == &primary { "primary" } else { "local" };
            let label = binding.peer_label(pid).unwrap_or_default();
            let label_suffix = if label.is_empty() {
                String::new()
            } else {
                format!("  \"{}\"", label)
            };
            format!("  {}  {}{}", short, role, label_suffix)
        })
        .collect();

    let remote_rows: Vec<String> = remotes
        .iter()
        .map(|pid| {
            let short = display::short_pid(pid);
            let label = binding.peer_label(pid).unwrap_or_default();
            let label_suffix = if label.is_empty() {
                String::new()
            } else {
                format!("  \"{}\"", label)
            };
            format!("  {}  connected{}", short, label_suffix)
        })
        .collect();

    VerbOutput::Listing {
        sections: vec![
            ListingSection::with_header(format!("local ({})", local_ids.len()), local_rows),
            ListingSection::with_header(format!("remote ({})", remotes.len()), remote_rows),
        ],
    }
}

/// Verb-op (§8.1). Submit a `CreatePeer` request and produce the
/// dispatched-state Info row.
pub fn peer_create_op(
    action_sink: &dyn AppActionSink,
    mode: PeerMode,
    label: Option<String>,
) -> VerbOutput {
    let label_disp = label.as_deref().unwrap_or("(unlabeled)").to_string();
    let mode_label = mode.label();
    action_sink.submit(ShellRequest::CreatePeer {
        mode,
        label,
    });
    VerbOutput::Info(vec![InfoRow::text(format!(
        "→ creating {} peer: {}",
        mode_label, label_disp
    ))])
}

/// Verb-op (§8.1). Submit a `DeletePeer` request for an already-
/// resolved bare peer-id (alias resolution is the verb-parser's job).
/// Errors if `peer_id` is the primary peer.
pub fn peer_delete_op(
    binding: &dyn PeerBinding,
    action_sink: &dyn AppActionSink,
    peer_id: String,
) -> Result<VerbOutput, ShellError> {
    if peer_id == binding.primary_peer_id() {
        return Err(ShellError::usage(
            "peer delete: refusing to delete the primary peer.",
        ));
    }
    let short = display::short_pid(&peer_id);
    action_sink.submit(ShellRequest::DeletePeer { peer_id });
    Ok(VerbOutput::Info(vec![InfoRow::text(format!(
        "→ deleting peer {}",
        short
    ))]))
}

/// Verb-op (§8.1). Submit a `RenamePeer` request for an already-
/// resolved bare peer-id with an optional new label (`None` clears).
pub fn peer_rename_op(
    action_sink: &dyn AppActionSink,
    peer_id: String,
    label: Option<String>,
) -> VerbOutput {
    let disp = label.as_deref().unwrap_or("(cleared)").to_string();
    let short = display::short_pid(&peer_id);
    action_sink.submit(ShellRequest::RenamePeer {
        peer_id,
        label,
    });
    VerbOutput::Info(vec![InfoRow::text(format!(
        "→ renaming peer {} → \"{}\"",
        short, disp
    ))])
}

/// Verb-parser (§8.1). Sub-op routing + arg-parsing + identifier-form
/// alias resolution. Delegates each sub-op to its verb-op.
pub fn peer(
    args: &[&str],
    binding: &dyn PeerBinding,
    action_sink: &dyn AppActionSink,
) -> Result<VerbOutput, ShellError> {
    match args.first().copied().unwrap_or("list") {
        "list" | "ls" => Ok(peer_list_op(binding)),
        "create" | "new" => peer_create_parser(&args[1..], action_sink),
        "delete" | "rm" | "remove" => peer_delete_parser(&args[1..], binding, action_sink),
        "rename" | "label" => peer_rename_parser(&args[1..], binding, action_sink),
        other => Err(ShellError::unknown(format!(
            "peer: unknown subcommand '{}'. Try: list, create, delete, rename.",
            other
        ))),
    }
}

fn peer_create_parser(
    args: &[&str],
    action_sink: &dyn AppActionSink,
) -> Result<VerbOutput, ShellError> {
    let mode_arg = args.first().ok_or_else(|| {
        ShellError::usage("peer create: usage: peer create <frontend|memory|opfs> [<label>]")
    })?;
    let mode = match *mode_arg {
        "frontend" | "front" => PeerMode::Frontend,
        "memory" | "mem" | "backend-memory" => PeerMode::BackendMemory,
        "opfs" | "backend-opfs" => PeerMode::BackendOpfs,
        other => {
            return Err(ShellError::unknown(format!(
                "peer create: unknown mode '{}'. Try: frontend, memory, opfs.",
                other
            )));
        }
    };
    let label = if args.len() > 1 {
        Some(args[1..].join(" "))
    } else {
        None
    };
    Ok(peer_create_op(action_sink, mode, label))
}

fn peer_delete_parser(
    args: &[&str],
    binding: &dyn PeerBinding,
    action_sink: &dyn AppActionSink,
) -> Result<VerbOutput, ShellError> {
    let target = args
        .first()
        .ok_or_else(|| ShellError::usage("peer delete: usage: peer delete <alias-or-pid>"))?;
    let pid = alias::resolve_pid(target, binding)
        .map_err(|msg| ShellError::not_found(format!("peer delete: {}", msg)))?;
    peer_delete_op(binding, action_sink, pid)
}

fn peer_rename_parser(
    args: &[&str],
    binding: &dyn PeerBinding,
    action_sink: &dyn AppActionSink,
) -> Result<VerbOutput, ShellError> {
    if args.len() < 2 {
        return Err(ShellError::usage(
            "peer rename: usage: peer rename <alias-or-pid> <new-label>",
        ));
    }
    let target = args[0];
    let new_label = args[1..].join(" ");
    let label_arg = if new_label.trim().is_empty() {
        None
    } else {
        Some(new_label.trim().to_string())
    };
    let pid = alias::resolve_pid(target, binding)
        .map_err(|msg| ShellError::not_found(format!("peer rename: {}", msg)))?;
    Ok(peer_rename_op(action_sink, pid, label_arg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};
    use std::cell::RefCell;

    struct StubBinding {
        primary: String,
        peers: Vec<String>,
        remotes: Vec<String>,
        labels: std::collections::HashMap<String, String>,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.primary }
        fn primary_peer_id(&self) -> String { self.primary.clone() }
        fn peer_ids(&self) -> Vec<String> { self.peers.clone() }
        fn connected_peers(&self) -> Vec<String> { self.remotes.clone() }
        fn peer_label(&self, pid: &str) -> Option<String> {
            self.labels.get(pid).cloned()
        }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }
    }

    struct RecordingSink {
        requests: RefCell<Vec<ShellRequest>>,
    }

    impl AppActionSink for RecordingSink {
        fn submit(&self, request: ShellRequest) {
            self.requests.borrow_mut().push(request);
        }
    }

    fn binding() -> StubBinding {
        StubBinding {
            primary: "alice_long_pid".into(),
            peers: vec!["alice_long_pid".into(), "bob".into()],
            remotes: vec!["remote1".into()],
            labels: [("bob".into(), "Bobby".into())].into_iter().collect(),
        }
    }

    fn sink() -> RecordingSink {
        RecordingSink { requests: RefCell::new(Vec::new()) }
    }

    #[test]
    fn list_returns_local_and_remote_sections() {
        let b = binding();
        let s = sink();
        match peer(&["list"], &b, &s).unwrap() {
            VerbOutput::Listing { sections } => {
                assert_eq!(sections.len(), 2);
                assert_eq!(sections[0].header.as_deref(), Some("local (2)"));
                assert_eq!(sections[1].header.as_deref(), Some("remote (1)"));
                assert!(sections[0].entries[0].contains("primary"));
                assert!(sections[0].entries[1].contains("Bobby"));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn create_submits_create_request() {
        let b = binding();
        let s = sink();
        let result = peer(&["create", "memory", "my", "label"], &b, &s).unwrap();
        assert!(matches!(result, VerbOutput::Info(_)));
        let req = s.requests.borrow();
        assert_eq!(req.len(), 1);
        let r0 = req[0].clone();
        drop(req);
        match r0 {
            ShellRequest::CreatePeer { mode, label } => {
                assert_eq!(mode, PeerMode::BackendMemory);
                assert_eq!(label.as_deref(), Some("my label"));
            }
            other => panic!("expected CreatePeer, got {:?}", other),
        }
    }

    #[test]
    fn create_unknown_mode_returns_unknown() {
        let b = binding();
        let s = sink();
        let err = peer(&["create", "wrong"], &b, &s).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Unknown);
    }

    #[test]
    fn delete_refuses_primary() {
        let b = binding();
        let s = sink();
        let err = peer(&["delete", "alice_long_pid"], &b, &s).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
        assert!(s.requests.borrow().is_empty());
    }

    #[test]
    fn delete_submits_delete_request_for_non_primary() {
        let b = binding();
        let s = sink();
        peer(&["delete", "bob"], &b, &s).unwrap();
        let req = s.requests.borrow()[0].clone();
        match req {
            ShellRequest::DeletePeer { peer_id } => assert_eq!(peer_id, "bob"),
            other => panic!("expected DeletePeer, got {:?}", other),
        }
    }

    #[test]
    fn rename_resolves_alias_and_submits_request() {
        let b = binding();
        let s = sink();
        peer(&["rename", "@Bobby", "new", "name"], &b, &s).unwrap();
        let req = s.requests.borrow()[0].clone();
        match req {
            ShellRequest::RenamePeer { peer_id, label } => {
                assert_eq!(peer_id, "bob");
                assert_eq!(label.as_deref(), Some("new name"));
            }
            other => panic!("expected RenamePeer, got {:?}", other),
        }
    }

    #[test]
    fn unknown_subcommand_returns_unknown() {
        let b = binding();
        let s = sink();
        let err = peer(&["bogus"], &b, &s).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Unknown);
    }

    #[test]
    fn peer_delete_op_refuses_primary() {
        let b = binding();
        let s = sink();
        let err = peer_delete_op(&b, &s, "alice_long_pid".into()).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn peer_rename_op_submits_request() {
        let s = sink();
        peer_rename_op(&s, "bob".into(), Some("new label".into()));
        let req = s.requests.borrow()[0].clone();
        match req {
            ShellRequest::RenamePeer { peer_id, label } => {
                assert_eq!(peer_id, "bob");
                assert_eq!(label.as_deref(), Some("new label"));
            }
            other => panic!("expected RenamePeer, got {:?}", other),
        }
    }
}
