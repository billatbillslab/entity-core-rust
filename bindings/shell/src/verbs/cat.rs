//! `cat` — print the entity at a path.
//!
//! Reads via `PeerBinding::get_entity`; formats the body with
//! `crate::format::entity_data` (CBOR pretty-print with hex fallback);
//! returns an `EntityView` carrying path, type, byte length, and body.
//!
//! Factored per guide §8.1 four-layer model: `cat_op` is the typed
//! verb-op (reusable by non-shell consumers), `cat` is the thin
//! verb-parser that resolves args against shell state and calls the
//! op. Alias expansion happens at the dispatcher tier — verb-parsers
//! receive already-expanded path arguments.

use crate::binding::PeerBinding;
use crate::format;
use crate::path;
use crate::result::{EntityView, ShellError, VerbOutput};
use crate::shell::Shell;

/// Verb-op (§8.1). Read the entity at `target` (an absolute path —
/// already alias-expanded by the dispatcher) and produce an
/// `EntityView`. Reusable from non-shell consumers (palette forms,
/// admin panels) without going through the verb-parser.
pub fn cat_op(
    binding: &dyn PeerBinding,
    target: &str,
) -> Result<VerbOutput, ShellError> {
    let entity = binding
        .get_entity(binding.peer_id(), target)
        .ok_or_else(|| ShellError::not_found(format!("cat: not found: {}", target)))?;
    let body = format::entity_data(&entity.data);
    Ok(VerbOutput::Entity(EntityView {
        path: target.to_string(),
        entity_type: entity.entity_type,
        byte_len: entity.data.len(),
        body,
    }))
}

/// Verb-parser (§8.1). Parses the path arg (already alias-expanded by
/// the dispatcher), resolves it against the shell's working directory,
/// and calls `cat_op`.
pub fn cat(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let path_arg = args
        .first()
        .ok_or_else(|| ShellError::usage("cat: missing path argument"))?;
    let target = path::resolve(shell.wd(), path_arg);
    cat_op(binding, &target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};

    struct StubBinding {
        bound: String,
        entities: Vec<(String, EntityRead)>,
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
        fn get_entity(&self, _pid: &str, path: &str) -> Option<EntityRead> {
            self.entities
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, e)| e.clone())
        }
    }

    fn cbor_text(s: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Text(s.into()), &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn returns_entity_with_formatted_body() {
        let b = StubBinding {
            bound: "alice".into(),
            entities: vec![(
                "/alice/note".into(),
                EntityRead {
                    entity_type: "app/note".into(),
                    data: cbor_text("hello"),
                    content_hash: String::new(),
                },
            )],
        };
        let shell = Shell::with_wd("alice", "/alice/");
        match cat(&shell, &["note"], &b).unwrap() {
            VerbOutput::Entity(view) => {
                assert_eq!(view.path, "/alice/note");
                assert_eq!(view.entity_type, "app/note");
                assert!(view.byte_len > 0);
                assert!(view.body.contains("\"hello\""));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn missing_path_returns_usage() {
        let b = StubBinding { bound: "alice".into(), entities: Vec::new() };
        let shell = Shell::with_wd("alice", "/alice/");
        let err = cat(&shell, &[], &b).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn missing_entity_returns_not_found() {
        let b = StubBinding { bound: "alice".into(), entities: Vec::new() };
        let shell = Shell::with_wd("alice", "/alice/");
        let err = cat(&shell, &["nothing"], &b).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::NotFound);
    }

    #[test]
    fn cat_op_with_resolved_path_returns_entity() {
        let b = StubBinding {
            bound: "alice".into(),
            entities: vec![(
                "/alice/note".into(),
                EntityRead {
                    entity_type: "app/note".into(),
                    data: cbor_text("hello"),
                    content_hash: String::new(),
                },
            )],
        };
        match cat_op(&b, "/alice/note").unwrap() {
            VerbOutput::Entity(view) => {
                assert_eq!(view.path, "/alice/note");
                assert_eq!(view.entity_type, "app/note");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }
}
