//! `pwd` — print the current working directory.
//!
//! Pattern-setter for Tier C verbs per `GUIDE-SHELL-FRAMING.md` §3.7:
//! pure function of `(shell, args) → Result<VerbOutput, ShellError>`.
//! No side effects, no scrollback writes, no awareness of the
//! consumer's render modality.
//!
//! Factored per guide §8.1 four-layer model: `pwd_op` is the typed
//! verb-op (takes wd-string + binding, applies §6.5 reverse-resolution
//! against the alias table); `pwd` is the verb-parser (extracts wd
//! from shell and calls op).
//!
//! Implements the §6.5 pin: the shell stores the *resolved* wd as the
//! single source of truth for dispatch; display reverse-resolves the
//! peer-id segment against the alias table at render time. Users with
//! labeled peers see `/@alice/foo`; users without labels see
//! `/{peer_id}/foo`. Alias-table changes after `cd` are reflected at
//! next `pwd` (no stale snapshots).

use crate::alias;
use crate::binding::PeerBinding;
use crate::path;
use crate::result::{ShellError, VerbOutput};
use crate::shell::Shell;

/// Verb-op (§8.1, §6.5). Reverse-resolve the peer-id segment of `wd`
/// against the alias table at display time. Returns the wd unchanged
/// when no label is set for the wd's peer (or when the wd doesn't have
/// the canonical `/{peer_id}/...` shape).
pub fn pwd_op(binding: &dyn PeerBinding, wd: &str) -> VerbOutput {
    let display = match path::peer_id_of(wd) {
        Some(pid) => match alias::reverse_lookup(&pid, binding) {
            Some(label) => {
                // Replace `/{pid}` prefix with `/@{label}`; keep the rest.
                let pid_prefix = format!("/{}", pid);
                let rest = wd.strip_prefix(&pid_prefix).unwrap_or(wd);
                format!("/@{}{}", label, rest)
            }
            None => wd.to_string(),
        },
        None => wd.to_string(),
    };
    VerbOutput::Path(display)
}

/// Verb-parser (§8.1). Extra positional args are ignored (matches
/// POSIX `pwd` behavior). Delegates to `pwd_op` for the §6.5
/// reverse-resolution.
pub fn pwd(
    shell: &Shell,
    _args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    Ok(pwd_op(binding, shell.wd()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};
    use std::collections::HashMap;

    struct StubBinding {
        bound: String,
        labels: HashMap<String, String>,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.bound }
        fn primary_peer_id(&self) -> String { self.bound.clone() }
        fn peer_ids(&self) -> Vec<String> { vec![self.bound.clone()] }
        fn connected_peers(&self) -> Vec<String> { Vec::new() }
        fn peer_label(&self, pid: &str) -> Option<String> {
            self.labels.get(pid).cloned()
        }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }
    }

    fn unlabeled() -> StubBinding {
        StubBinding { bound: "alice".into(), labels: HashMap::new() }
    }

    fn labeled() -> StubBinding {
        let mut labels = HashMap::new();
        labels.insert("alice".into(), "Alice".into());
        StubBinding { bound: "alice".into(), labels }
    }

    #[test]
    fn returns_wd_as_path_variant() {
        let shell = Shell::new("alice");
        let b = unlabeled();
        match pwd(&shell, &[], &b).unwrap() {
            VerbOutput::Path(p) => assert_eq!(p, "/alice/"),
            other => panic!("expected Path variant, got {:?}", other),
        }
    }

    #[test]
    fn returns_explicit_wd_after_set() {
        let mut shell = Shell::new("alice");
        shell.set_wd("/alice/app/entity-browser/");
        let b = unlabeled();
        match pwd(&shell, &[], &b).unwrap() {
            VerbOutput::Path(p) => assert_eq!(p, "/alice/app/entity-browser/"),
            other => panic!("expected Path variant, got {:?}", other),
        }
    }

    #[test]
    fn extra_args_ignored() {
        let shell = Shell::new("alice");
        let b = unlabeled();
        let result = pwd(&shell, &["unexpected", "args"], &b);
        assert!(matches!(result, Ok(VerbOutput::Path(_))));
    }

    #[test]
    fn reverse_resolves_to_label_when_present() {
        let mut shell = Shell::new("alice");
        shell.set_wd("/alice/system/");
        let b = labeled();
        match pwd(&shell, &[], &b).unwrap() {
            VerbOutput::Path(p) => assert_eq!(p, "/@Alice/system/"),
            other => panic!("expected Path variant, got {:?}", other),
        }
    }

    #[test]
    fn falls_back_to_resolved_form_when_no_label() {
        let mut shell = Shell::new("alice");
        shell.set_wd("/alice/system/");
        let b = unlabeled();
        match pwd(&shell, &[], &b).unwrap() {
            VerbOutput::Path(p) => assert_eq!(p, "/alice/system/"),
            other => panic!("expected Path variant, got {:?}", other),
        }
    }

    #[test]
    fn pwd_op_with_label_returns_alias_form() {
        let b = labeled();
        match pwd_op(&b, "/alice/foo") {
            VerbOutput::Path(p) => assert_eq!(p, "/@Alice/foo"),
            other => panic!("expected Path variant, got {:?}", other),
        }
    }
}
