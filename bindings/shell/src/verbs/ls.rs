//! `ls` — list children at a path.
//!
//! Pure read against `PeerBinding::tree_listing`. Returns the bound
//! peer's children at the resolved prefix; verbs targeting another
//! peer's mirror use `cd` to reach the prefix first (shell scope is
//! the bound peer's tree, per guide §4.1).
//!
//! Factored per guide §8.1 four-layer model: `ls_op` is the typed
//! verb-op; `ls` is the verb-parser. Alias expansion happens at the
//! dispatcher tier — `ls` receives an already-expanded path arg.

use crate::binding::PeerBinding;
use crate::path;
use crate::result::{ListingSection, ShellError, VerbOutput};
use crate::shell::Shell;

/// Verb-op (§8.1). List children at `prefix` (an absolute path —
/// already alias-expanded by the dispatcher). Empty result becomes a
/// single section with `(empty: <prefix>)` as the header.
pub fn ls_op(
    binding: &dyn PeerBinding,
    prefix: &str,
) -> Result<VerbOutput, ShellError> {
    let entries = binding.tree_listing(binding.peer_id(), prefix);
    if entries.is_empty() {
        return Ok(VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                format!("(empty: {})", prefix),
                Vec::new(),
            )],
        });
    }
    Ok(VerbOutput::Listing {
        sections: vec![ListingSection::flat(
            entries.into_iter().map(|e| e.path).collect(),
        )],
    })
}

/// Verb-parser (§8.1). Resolves the optional path arg against the
/// shell's working directory, then calls `ls_op`.
///
/// - `ls` → children at the current wd.
/// - `ls <path>` → resolves relative/absolute paths against wd.
pub fn ls(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let prefix = match args.first() {
        Some(t) => path::resolve(shell.wd(), t),
        None => shell.wd().to_string(),
    };
    ls_op(binding, &prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::TreeListingEntry;

    struct StubBinding {
        bound: String,
        listing: Vec<(String, Vec<TreeListingEntry>)>,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.bound }
        fn primary_peer_id(&self) -> String { self.bound.clone() }
        fn peer_ids(&self) -> Vec<String> { vec![self.bound.clone()] }
        fn connected_peers(&self) -> Vec<String> { Vec::new() }
        fn peer_label(&self, _pid: &str) -> Option<String> { None }
        fn tree_listing(&self, _pid: &str, prefix: &str) -> Vec<TreeListingEntry> {
            self.listing
                .iter()
                .find(|(p, _)| p == prefix)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<crate::binding::EntityRead> {
            None
        }
    }

    fn entry(path: &str) -> TreeListingEntry {
        TreeListingEntry { path: path.into() }
    }

    #[test]
    fn lists_wd_when_no_args() {
        let b = StubBinding {
            bound: "alice".into(),
            listing: vec![(
                "/alice/".into(),
                vec![entry("/alice/system"), entry("/alice/app")],
            )],
        };
        let shell = Shell::with_wd("alice", "/alice/");
        match ls(&shell, &[], &b).unwrap() {
            VerbOutput::Listing { sections } => {
                assert_eq!(sections.len(), 1);
                assert_eq!(sections[0].header, None);
                assert_eq!(sections[0].entries, vec!["/alice/system", "/alice/app"]);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn resolves_relative_path() {
        let b = StubBinding {
            bound: "alice".into(),
            listing: vec![(
                "/alice/system".into(),
                vec![entry("/alice/system/identity")],
            )],
        };
        let shell = Shell::with_wd("alice", "/alice/");
        match ls(&shell, &["system"], &b).unwrap() {
            VerbOutput::Listing { sections } => {
                assert_eq!(sections[0].entries, vec!["/alice/system/identity"]);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn empty_listing_uses_empty_header() {
        let b = StubBinding {
            bound: "alice".into(),
            listing: Vec::new(),
        };
        let shell = Shell::with_wd("alice", "/alice/");
        match ls(&shell, &[], &b).unwrap() {
            VerbOutput::Listing { sections } => {
                assert_eq!(sections[0].header.as_deref(), Some("(empty: /alice/)"));
                assert!(sections[0].entries.is_empty());
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn ls_op_lists_at_resolved_prefix() {
        let b = StubBinding {
            bound: "alice".into(),
            listing: vec![(
                "/alice/system".into(),
                vec![entry("/alice/system/identity")],
            )],
        };
        match ls_op(&b, "/alice/system").unwrap() {
            VerbOutput::Listing { sections } => {
                assert_eq!(sections[0].entries, vec!["/alice/system/identity"]);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }
}
