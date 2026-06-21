//! `tail <prefix>` / `tails` / `untail <pfx|all>` — subscription
//! lifecycle.
//!
//! Subscription state (WindowWatch handles, ChangeOp callbacks) is
//! embedding-specific and stays embedding-side. The verbs go through
//! `AppActionSink`:
//!
//! - `tail`   → `InstallTail { prefix }` request + dispatched-state
//!              Info row.
//! - `tails`  → reads `AppActionSink::list_tails()`; renders as a
//!              `Listing` with "active tails (N)" header.
//! - `untail` → `UninstallTail { target }` request + Message ack.
//!
//! Per `SHELL-EXTRACTION-PHASE-1-NOTES.md` KNOT F: the streaming-Lines
//! subscription shape is a future direction. Today's verb is "install
//! and forget" — the embedding pushes change events into scrollback
//! through its own channels.

use crate::action::{AppActionSink, ShellRequest};
use crate::binding::PeerBinding;
use crate::path;
use crate::result::{InfoRow, ListingSection, ShellError, VerbOutput};
use crate::shell::Shell;

/// Verb-op (§8.1). Submit an `InstallTail` request against a fully-
/// resolved and trailing-slash-terminated prefix. The prefix MUST be
/// `/<peer_id>/...` with a trailing slash (semantic: prefix
/// subscription matches descendants only — `/p/foo/` not
/// `/p/foobar`). Caller (verb-parser or non-shell consumer) is
/// responsible for the trailing-slash and peer-id validation.
pub fn tail_op(
    action_sink: &dyn AppActionSink,
    prefix: &str,
) -> VerbOutput {
    action_sink.submit(ShellRequest::InstallTail {
        prefix: prefix.to_string(),
    });
    VerbOutput::Info(vec![InfoRow::text(format!(
        "→ tail {} (Ctrl-L to clear, close window to stop)",
        prefix
    ))])
}

/// Verb-parser (§8.1). Resolves the path-prefix arg against the
/// shell's wd, appends a trailing slash (semantic for prefix
/// subscriptions — `path::resolve` strips trailing slashes on absolute
/// inputs so we restore it here), validates the peer-id, then calls
/// `tail_op`. Alias expansion happens at the dispatcher tier.
pub fn tail(
    shell: &Shell,
    args: &[&str],
    _binding: &dyn PeerBinding,
    action_sink: &dyn AppActionSink,
) -> Result<VerbOutput, ShellError> {
    let prefix_arg = args
        .first()
        .ok_or_else(|| ShellError::usage("tail: usage: tail <path-prefix>"))?;
    let mut resolved = path::resolve(shell.wd(), prefix_arg);
    if !resolved.ends_with('/') {
        resolved.push('/');
    }
    if path::peer_id_of(&resolved).is_none() {
        return Err(ShellError::usage(format!(
            "tail: invalid prefix '{}' (expected /<peer_id>/...)",
            resolved
        )));
    }
    Ok(tail_op(action_sink, &resolved))
}

/// Verb-op-shaped by construction (§8.1): no `Shell`, no binding, no
/// path args, no parser/op seam to factor. Takes only the action-sink
/// and returns a `Listing` of currently-installed tails.
pub fn tails(action_sink: &dyn AppActionSink) -> Result<VerbOutput, ShellError> {
    let entries = action_sink.list_tails();
    if entries.is_empty() {
        return Ok(VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                "(no active tails)",
                Vec::new(),
            )],
        });
    }
    let active_count = entries.iter().filter(|t| t.active).count();
    let rows: Vec<String> = entries
        .iter()
        .map(|t| {
            let status = if t.active { "active" } else { "stopped" };
            format!("  {}  [{}]", t.prefix, status)
        })
        .collect();
    Ok(VerbOutput::Listing {
        sections: vec![ListingSection::with_header(
            format!("active tails ({})", active_count),
            rows,
        )],
    })
}

/// Verb-op (§8.1). Submit an `UninstallTail` request against a fully-
/// validated target (literal prefix string or `"all"`). Caller is
/// responsible for arg-validation. Reusable from non-shell consumers
/// driving subscription teardown (e.g., a tails-management panel).
pub fn untail_op(
    action_sink: &dyn AppActionSink,
    target: &str,
) -> VerbOutput {
    action_sink.submit(ShellRequest::UninstallTail {
        target: target.to_string(),
    });
    VerbOutput::Message(format!("untail: requested stop for {}", target))
}

/// Verb-parser (§8.1). Validates the target arg and calls `untail_op`.
/// The target is treated opaquely (the embedding's action-sink
/// resolves prefix vs `"all"` semantics); no path resolution or alias
/// expansion happens at the shell layer for `untail`.
pub fn untail(
    args: &[&str],
    action_sink: &dyn AppActionSink,
) -> Result<VerbOutput, ShellError> {
    let target = args
        .first()
        .copied()
        .ok_or_else(|| ShellError::usage("untail: usage: untail <prefix|all>"))?;
    Ok(untail_op(action_sink, target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::TailInfo;
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
        tails: Vec<TailInfo>,
        requests: RefCell<Vec<ShellRequest>>,
    }

    impl AppActionSink for StubSink {
        fn submit(&self, request: ShellRequest) {
            self.requests.borrow_mut().push(request);
        }
        fn list_tails(&self) -> Vec<TailInfo> {
            self.tails.clone()
        }
    }

    fn sink() -> StubSink {
        StubSink { tails: Vec::new(), requests: RefCell::new(Vec::new()) }
    }

    #[test]
    fn tail_missing_arg_returns_usage() {
        let s = sink();
        let shell = Shell::with_wd("alice", "/alice/");
        let err = tail(&shell, &[], &StubBinding, &s).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn tail_resolves_relative_and_appends_slash() {
        let s = sink();
        let shell = Shell::with_wd("alice", "/alice/");
        tail(&shell, &["system"], &StubBinding, &s).unwrap();
        let req = s.requests.borrow()[0].clone();
        match req {
            ShellRequest::InstallTail { prefix } => assert_eq!(prefix, "/alice/system/"),
            other => panic!("expected InstallTail, got {:?}", other),
        }
    }

    #[test]
    fn tails_returns_empty_marker_when_no_subscriptions() {
        let s = sink();
        match tails(&s).unwrap() {
            VerbOutput::Listing { sections } => {
                assert_eq!(sections[0].header.as_deref(), Some("(no active tails)"));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn tails_lists_active_and_stopped_subscriptions() {
        let s = StubSink {
            tails: vec![
                TailInfo { prefix: "/alice/foo/".into(), active: true },
                TailInfo { prefix: "/alice/bar/".into(), active: false },
            ],
            requests: RefCell::new(Vec::new()),
        };
        match tails(&s).unwrap() {
            VerbOutput::Listing { sections } => {
                assert!(sections[0].header.as_ref().unwrap().contains("active tails (1)"));
                assert!(sections[0].entries[0].contains("[active]"));
                assert!(sections[0].entries[1].contains("[stopped]"));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn untail_submits_request() {
        let s = sink();
        untail(&["all"], &s).unwrap();
        let req = s.requests.borrow()[0].clone();
        match req {
            ShellRequest::UninstallTail { target } => assert_eq!(target, "all"),
            other => panic!("expected UninstallTail, got {:?}", other),
        }
    }
}
