//! `cd` — change the working directory.
//!
//! First peer-touching verb; forces `PeerBinding` (peer-id lookup for
//! bare-cd root) and `SelectionSink` (post-navigation publish) trait
//! surfaces per `GUIDE-SHELL-FRAMING.md` §3.5–§3.7. The Selection
//! publish is the shell's hook into the panel-source substrate.
//!
//! Factored per guide §8.1 four-layer model: `cd_op` is the pure
//! verb-op that resolves and validates a target path; `cd` is the
//! verb-parser that mutates the shell's wd and publishes to the sink.
//! Alias expansion happens at the dispatcher tier — `cd` receives an
//! already-expanded path arg.

use crate::binding::PeerBinding;
use crate::path;
use crate::result::{ShellError, VerbOutput};
use crate::shell::Shell;
use crate::sink::SelectionSink;

/// Verb-op (§8.1). Resolve and validate the target wd given the
/// current wd and an optional path arg (already alias-expanded by the
/// dispatcher). Bare invocation (`path_arg = None`) returns the bound
/// peer's root.
///
/// Pure: no mutation, no side effects. Non-shell consumers (a palette
/// form that wants to validate a "navigate to" target before
/// committing) can call this directly.
pub fn cd_op(
    binding: &dyn PeerBinding,
    current_wd: &str,
    path_arg: Option<&str>,
) -> Result<String, ShellError> {
    let target = match path_arg {
        Some(t) => path::resolve(current_wd, t),
        None => format!("/{}/", binding.peer_id()),
    };
    if path::peer_id_of(&target).is_none() {
        return Err(ShellError::usage(format!(
            "cd: invalid path '{}' (expected /<peer_id>/...)",
            target
        )));
    }
    Ok(target)
}

/// Verb-parser (§8.1). Calls `cd_op`, then mutates shell.wd and
/// publishes the new wd to the optional sink.
///
/// - Bare `cd` → jump to the bound peer's root (POSIX `cd` ≡ `$HOME`).
/// - `cd <path>` → resolve against current wd; supports absolute,
///   relative, and `..` (capped at peer root). Alias expansion (e.g.,
///   `@self/...`) is performed by the dispatcher before reaching here.
pub fn cd(
    shell: &mut Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    sink: Option<&dyn SelectionSink>,
) -> Result<VerbOutput, ShellError> {
    let new_wd = cd_op(binding, shell.wd(), args.first().copied())?;
    shell.set_wd(new_wd.clone());
    if let Some(s) = sink {
        s.publish(&new_wd);
    }
    Ok(VerbOutput::Message(format!("cd: {}", new_wd)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct StubBinding {
        bound: String,
        primary: String,
        peers: Vec<String>,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.bound }
        fn primary_peer_id(&self) -> String { self.primary.clone() }
        fn peer_ids(&self) -> Vec<String> { self.peers.clone() }
        fn connected_peers(&self) -> Vec<String> { Vec::new() }
        fn peer_label(&self, _pid: &str) -> Option<String> { None }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<crate::binding::TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<crate::binding::EntityRead> {
            None
        }
    }

    fn stub() -> StubBinding {
        StubBinding {
            bound: "alice".into(),
            primary: "alice".into(),
            peers: vec!["alice".into()],
        }
    }

    struct RecordingSink {
        published: RefCell<Vec<String>>,
    }

    impl SelectionSink for RecordingSink {
        fn publish(&self, path: &str) {
            self.published.borrow_mut().push(path.to_string());
        }
    }

    #[test]
    fn bare_cd_returns_to_peer_root() {
        let mut shell = Shell::with_wd("alice", "/alice/system/");
        let b = stub();
        let sink = RecordingSink { published: RefCell::new(Vec::new()) };
        let result = cd(&mut shell, &[], &b, Some(&sink)).unwrap();
        assert!(matches!(result, VerbOutput::Message(ref m) if m == "cd: /alice/"));
        assert_eq!(shell.wd(), "/alice/");
        assert_eq!(sink.published.borrow().as_slice(), &["/alice/"]);
    }

    #[test]
    fn relative_path_joins_against_wd() {
        let mut shell = Shell::with_wd("alice", "/alice/");
        let b = stub();
        cd(&mut shell, &["system"], &b, None).unwrap();
        assert_eq!(shell.wd(), "/alice/system");
    }

    #[test]
    fn absolute_path_replaces() {
        let mut shell = Shell::with_wd("alice", "/alice/system/");
        let b = stub();
        // Absolute inputs are normalized; trailing slashes don't survive
        // (matches the resolve_path semantics lifted from egui).
        cd(&mut shell, &["/alice/app/"], &b, None).unwrap();
        assert_eq!(shell.wd(), "/alice/app");
    }

    #[test]
    fn dot_dot_capped_at_peer_root() {
        let mut shell = Shell::with_wd("alice", "/alice/sys/sub/");
        let b = stub();
        cd(&mut shell, &["../../../../.."], &b, None).unwrap();
        assert_eq!(shell.wd(), "/alice/");
    }

    #[test]
    fn sink_called_on_success() {
        let mut shell = Shell::with_wd("alice", "/alice/");
        let b = stub();
        let sink = RecordingSink { published: RefCell::new(Vec::new()) };
        cd(&mut shell, &["system"], &b, Some(&sink)).unwrap();
        assert_eq!(sink.published.borrow().as_slice(), &["/alice/system"]);
    }

    #[test]
    fn cd_op_returns_resolved_target() {
        let b = stub();
        let new_wd = cd_op(&b, "/alice/", Some("system")).unwrap();
        assert_eq!(new_wd, "/alice/system");
    }

    #[test]
    fn cd_op_bare_returns_peer_root() {
        let b = stub();
        let new_wd = cd_op(&b, "/alice/system/", None).unwrap();
        assert_eq!(new_wd, "/alice/");
    }
}
