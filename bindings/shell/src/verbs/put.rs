//! `put <path> <type> [<json-body>]` — write an entity into the tree.
//!
//! Renamed from `set` per `GUIDE-SHELL-FRAMING.md` §4.5 (cross-impl
//! 9-core convergence with `EXTENSION-TREE` primitive ops). Sync;
//! dispatch via `PeerBinding::put_entity`. JSON parsing of the
//! optional body is the embedding's concern — see the trait docs.
//!
//! Factored per guide §8.1 four-layer model: `put_op` is the typed
//! verb-op; `put` is the verb-parser. Alias expansion happens at the
//! dispatcher tier — `put` receives an already-expanded path arg.

use crate::binding::PeerBinding;
use crate::path;
use crate::result::{ShellError, VerbOutput};
use crate::shell::Shell;

/// Verb-op (§8.1). Write a `type_name`-typed entity at `target` (an
/// absolute path — already alias-expanded by the dispatcher), with an
/// optional CBOR body parsed by the embedding.
pub fn put_op(
    binding: &dyn PeerBinding,
    target: &str,
    type_name: &str,
    params_text: Option<String>,
) -> Result<VerbOutput, ShellError> {
    if path::peer_id_of(target).is_none() {
        return Err(ShellError::usage(format!(
            "put: invalid path '{}' (expected /<peer_id>/...)",
            target
        )));
    }
    binding
        .put_entity(binding.peer_id(), target, type_name, params_text)
        .map_err(|e| ShellError::dispatch(format!("put: {}", e)))?;
    Ok(VerbOutput::Message(format!(
        "put: {} (type={})",
        target, type_name
    )))
}

/// Verb-parser (§8.1). Resolves the path arg against the shell's
/// working directory, joins any trailing args into a JSON body, then
/// calls `put_op`.
pub fn put(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    if args.len() < 2 {
        return Err(ShellError::usage(
            "put: usage: put <path> <type> [<json-body>]",
        ));
    }
    let path_arg = args[0];
    let type_name = args[1];
    let target = path::resolve(shell.wd(), path_arg);
    let params_text = if args.len() > 2 {
        let joined = args[2..].join(" ");
        if joined.trim().is_empty() { None } else { Some(joined) }
    } else {
        None
    };
    put_op(binding, &target, type_name, params_text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};
    use std::cell::RefCell;

    struct StubBinding {
        bound: String,
        writes: RefCell<Vec<(String, String, Option<String>)>>,
        err: Option<String>,
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
        fn put_entity(
            &self,
            _pid: &str,
            path: &str,
            entity_type: &str,
            params_text: Option<String>,
        ) -> Result<(), String> {
            if let Some(e) = &self.err { return Err(e.clone()); }
            self.writes.borrow_mut().push((
                path.to_string(),
                entity_type.to_string(),
                params_text,
            ));
            Ok(())
        }
    }

    #[test]
    fn too_few_args_returns_usage() {
        let b = StubBinding { bound: "alice".into(), writes: RefCell::new(Vec::new()), err: None };
        let shell = Shell::with_wd("alice", "/alice/");
        let err = put(&shell, &["only-path"], &b).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn writes_entity_and_returns_message() {
        let b = StubBinding { bound: "alice".into(), writes: RefCell::new(Vec::new()), err: None };
        let shell = Shell::with_wd("alice", "/alice/");
        let result = put(&shell, &["notes/today", "app/note"], &b).unwrap();
        assert!(matches!(result, VerbOutput::Message(ref m) if m.contains("/alice/notes/today")));
        let writes = b.writes.borrow();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, "/alice/notes/today");
        assert_eq!(writes[0].1, "app/note");
        assert!(writes[0].2.is_none());
    }

    #[test]
    fn forwards_json_body_to_binding() {
        let b = StubBinding { bound: "alice".into(), writes: RefCell::new(Vec::new()), err: None };
        let shell = Shell::with_wd("alice", "/alice/");
        put(&shell, &["x", "t", "{\"k\":1}"], &b).unwrap();
        let writes = b.writes.borrow();
        assert_eq!(writes[0].2.as_deref(), Some("{\"k\":1}"));
    }

    #[test]
    fn binding_error_becomes_dispatch_err() {
        let b = StubBinding {
            bound: "alice".into(),
            writes: RefCell::new(Vec::new()),
            err: Some("bad cbor".into()),
        };
        let shell = Shell::with_wd("alice", "/alice/");
        let err = put(&shell, &["x", "t"], &b).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Dispatch);
    }

    #[test]
    fn put_op_writes_at_resolved_target() {
        let b = StubBinding { bound: "alice".into(), writes: RefCell::new(Vec::new()), err: None };
        put_op(&b, "/alice/notes/today", "app/note", None).unwrap();
        let writes = b.writes.borrow();
        assert_eq!(writes[0].0, "/alice/notes/today");
        assert_eq!(writes[0].1, "app/note");
    }
}
