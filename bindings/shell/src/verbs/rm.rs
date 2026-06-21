//! `rm <path>` — remove the entity at a path.
//!
//! Sync; dispatch via `PeerBinding::remove_entity`.
//!
//! Factored per guide §8.1 four-layer model: `rm_op` is the typed
//! verb-op; `rm` is the verb-parser. Alias expansion happens at the
//! dispatcher tier — `rm` receives an already-expanded path arg.

use crate::binding::PeerBinding;
use crate::path;
use crate::result::{ShellError, VerbOutput};
use crate::shell::Shell;

/// Verb-op (§8.1). Remove the entity at `target` (an absolute path —
/// already alias-expanded by the dispatcher).
pub fn rm_op(
    binding: &dyn PeerBinding,
    target: &str,
) -> Result<VerbOutput, ShellError> {
    if path::peer_id_of(target).is_none() {
        return Err(ShellError::usage(format!(
            "rm: invalid path '{}' (expected /<peer_id>/...)",
            target
        )));
    }
    binding.remove_entity(binding.peer_id(), target);
    Ok(VerbOutput::Message(format!("rm: {}", target)))
}

/// Verb-parser (§8.1). Resolves the path arg against the shell's
/// working directory, then calls `rm_op`.
pub fn rm(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let target_arg = args
        .first()
        .ok_or_else(|| ShellError::usage("rm: usage: rm <path>"))?;
    let target = path::resolve(shell.wd(), target_arg);
    rm_op(binding, &target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};
    use std::cell::RefCell;

    struct StubBinding {
        bound: String,
        removed: RefCell<Vec<String>>,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.bound }
        fn primary_peer_id(&self) -> String { self.bound.clone() }
        fn peer_ids(&self) -> Vec<String> { vec![self.bound.clone()] }
        fn connected_peers(&self) -> Vec<String> { Vec::new() }
        fn peer_label(&self, _pid: &str) -> Option<String> { None }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }
        fn remove_entity(&self, _pid: &str, path: &str) {
            self.removed.borrow_mut().push(path.to_string());
        }
    }

    #[test]
    fn missing_arg_returns_usage() {
        let b = StubBinding { bound: "alice".into(), removed: RefCell::new(Vec::new()) };
        let shell = Shell::with_wd("alice", "/alice/");
        let err = rm(&shell, &[], &b).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn removes_entity_and_returns_message() {
        let b = StubBinding { bound: "alice".into(), removed: RefCell::new(Vec::new()) };
        let shell = Shell::with_wd("alice", "/alice/");
        let result = rm(&shell, &["notes/today"], &b).unwrap();
        assert!(matches!(result, VerbOutput::Message(ref m) if m == "rm: /alice/notes/today"));
        assert_eq!(b.removed.borrow().as_slice(), &["/alice/notes/today"]);
    }

    #[test]
    fn rm_op_removes_at_resolved_target() {
        let b = StubBinding { bound: "alice".into(), removed: RefCell::new(Vec::new()) };
        let result = rm_op(&b, "/alice/notes/today").unwrap();
        assert!(matches!(result, VerbOutput::Message(ref m) if m == "rm: /alice/notes/today"));
        assert_eq!(b.removed.borrow().as_slice(), &["/alice/notes/today"]);
    }
}
