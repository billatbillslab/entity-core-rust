//! `disconnect <peer-or-alias>` — per guide §4.7.
//!
//! Idempotent against already-closed connections (returns `Message`,
//! not error). Unknown peer/alias returns `NotFound`. Does not affect
//! the bound peer's binding — only tears down the connection registry
//! entry via `PeerBinding::remove_connection`.
//!
//! **Limitation (cross-impl):** SDK-level transport teardown isn't
//! wired yet (`Peers` has no `disconnect_peer` symmetric to
//! `connect_peer`). This verb removes the peer from the embedding's
//! connections registry only — the underlying transport remains open
//! in the SDK pool. The user-facing message reflects that.
//!
//! Factored per guide §8.1 four-layer model: `disconnect_op` is the
//! typed verb-op (takes a pre-resolved bare peer-id, not an alias);
//! `disconnect` is the verb-parser. Alias-to-pid resolution happens
//! at the dispatcher tier via `alias::resolve_pid` (identifier-form
//! expansion per §6.2 standalone-`@alias` usage — distinct from path-
//! form expansion).

use crate::binding::PeerBinding;
use crate::display;
use crate::result::{ShellError, VerbOutput};
use crate::shell::Shell;

/// Verb-op (§8.1). Disconnect `peer_id` (a bare peer-id, not an
/// alias — alias resolution happens at the dispatcher tier) from the
/// embedding's connection registry. Idempotent against already-closed
/// connections (returns a `Message` variant, not an error).
pub fn disconnect_op(
    binding: &dyn PeerBinding,
    peer_id: &str,
) -> VerbOutput {
    let connected = binding.connected_peers();
    if !connected.contains(&peer_id.to_string()) {
        return VerbOutput::Message(format!(
            "disconnect: not connected to {} (no action)",
            display::short_pid(peer_id)
        ));
    }
    binding.remove_connection(peer_id);
    VerbOutput::Message(format!(
        "disconnect: closed connection to {} (registry only — SDK transport teardown is upstream TODO)",
        display::short_pid(peer_id)
    ))
}

/// Verb-parser (§8.1). Receives an already-resolved peer-id (the
/// dispatcher expands `@alias` to bare pid via `alias::resolve_pid`)
/// and calls `disconnect_op`.
pub fn disconnect(
    _shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let target = args.first().ok_or_else(|| {
        ShellError::usage("disconnect: usage: disconnect <peer-or-alias>")
    })?;
    Ok(disconnect_op(binding, target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};
    use std::cell::RefCell;

    struct StubBinding {
        bound: String,
        connected: RefCell<Vec<String>>,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.bound }
        fn primary_peer_id(&self) -> String { self.bound.clone() }
        fn peer_ids(&self) -> Vec<String> { vec![self.bound.clone()] }
        fn connected_peers(&self) -> Vec<String> { self.connected.borrow().clone() }
        fn peer_label(&self, _pid: &str) -> Option<String> { None }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }
        fn remove_connection(&self, peer_id: &str) {
            self.connected.borrow_mut().retain(|p| p != peer_id);
        }
    }

    #[test]
    fn missing_arg_returns_usage() {
        let b = StubBinding { bound: "alice".into(), connected: RefCell::new(Vec::new()) };
        let shell = Shell::with_wd("alice", "/alice/");
        let err = disconnect(&shell, &[], &b).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn idempotent_when_not_connected() {
        let b = StubBinding { bound: "alice".into(), connected: RefCell::new(Vec::new()) };
        let shell = Shell::with_wd("alice", "/alice/");
        match disconnect(&shell, &["remote1"], &b).unwrap() {
            VerbOutput::Message(m) => assert!(m.contains("no action")),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn removes_from_registry_when_connected() {
        let b = StubBinding {
            bound: "alice".into(),
            connected: RefCell::new(vec!["remote1".into()]),
        };
        let shell = Shell::with_wd("alice", "/alice/");
        match disconnect(&shell, &["remote1"], &b).unwrap() {
            VerbOutput::Message(m) => assert!(m.contains("closed connection")),
            other => panic!("unexpected variant: {:?}", other),
        }
        assert!(b.connected.borrow().is_empty());
    }

    #[test]
    fn disconnect_op_with_resolved_pid_removes_from_registry() {
        let b = StubBinding {
            bound: "alice".into(),
            connected: RefCell::new(vec!["remote1".into()]),
        };
        let result = disconnect_op(&b, "remote1");
        assert!(matches!(result, VerbOutput::Message(ref m) if m.contains("closed connection")));
        assert!(b.connected.borrow().is_empty());
    }
}
