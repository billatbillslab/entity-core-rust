//! Verb routing — the crate's single dispatch entry point.
//!
//! Embeddings call `dispatch(line, shell, binding, sink, spawn)` once
//! per submitted line. The dispatcher parses the line into verb +
//! args, routes to the appropriate Tier C verb, and returns either:
//!
//! - `Some(Ok(VerbOutput))` — verb handled, result rendered by adapter.
//! - `Some(Err(ShellError))` — verb known but failed (bad args, missing
//!   path, dispatch error). Adapter renders as a styled error line.
//! - `None` — verb not in the crate's vocabulary. Embeddings with
//!   extra verbs (Tier E ops like `query`/`count`/`peer` in egui)
//!   fall through to their own routing.
//!
//! Empty lines return `Some(Ok(VerbOutput::Message(""))` after recording
//! the submit for history. Actually we just early-return `None` for
//! empty lines — the embedding's history bookkeeping covers them.
//!
//! Tab completion is **not** in this module today — it lives in the
//! embedding's controller. Future Phase 3b sub-slice can lift the
//! verb-name + path completers here.

use crate::action::AppActionSink;
use crate::alias;
use crate::binding::PeerBinding;
use crate::result::{ShellError, VerbOutput};
use crate::runtime::BoxFuture;
use crate::shell::Shell;
use crate::sink::SelectionSink;
use crate::verbs;

/// All verbs the crate's dispatcher recognizes. Embeddings can
/// inspect this list (e.g., for tab completion or to decide whether
/// to route through the crate).
pub const VERBS: &[&str] = &[
    "help", "pwd", "cd", "ls", "cat", "tree", "info",
    "disconnect", "connect", "exec",
    "put", "rm",
    "query", "count",
    "peer", "peers", "open",
    "tail", "tails", "untail",
    "compute", "bootstrap",
    "inspect",
];

/// Returns `true` when `verb` is recognized by the crate's dispatcher.
pub fn handles(verb: &str) -> bool {
    VERBS.iter().any(|v| *v == verb)
}

/// Parse a submitted line into `(verb, args)`. Returns `None` for
/// empty or whitespace-only input. The first whitespace-separated
/// token is the verb; remaining tokens are positional args.
pub fn parse(line: &str) -> Option<(&str, Vec<&str>)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let verb = parts.next()?;
    let args: Vec<&str> = parts.collect();
    Some((verb, args))
}

/// Dispatch one submitted line.
///
/// - `shell` — session state (peer_id + wd). `cd` mutates wd; other
///   verbs read.
/// - `binding` — embedding's `PeerBinding` impl. Verbs invoke tree
///   ops, dispatch, alias resolution through this.
/// - `sink` — optional. When `Some`, `cd` publishes the new wd via
///   the sink (the panel-source substrate hook); `None` opts out of
///   co-orientation publishing.
/// - `action_sink` — `AppActionSink` for lifecycle verbs (`peer`,
///   `open`, `tail`/`tails`/`untail`). Embeddings without lifecycle
///   support can pass `&()` (the no-op default impl); affected
///   verbs degrade gracefully.
/// - `spawn` — `FnOnce` closure called by async verbs (`connect`,
///   `exec`, `query`, `count`) with the producer task. Sync verbs
///   ignore (drop) the closure.
///
/// Returns `Some` when the line's verb is in `VERBS`; `None`
/// otherwise. Empty / whitespace-only lines return `None`.
pub fn dispatch<S>(
    line: &str,
    shell: &mut Shell,
    binding: &dyn PeerBinding,
    sink: Option<&dyn SelectionSink>,
    action_sink: &dyn AppActionSink,
    spawn: S,
) -> Option<Result<VerbOutput, ShellError>>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (verb, args) = parse(line)?;
    let result = match verb {
        "help" => verbs::help(&args),
        "pwd" => verbs::pwd(shell, &args, binding), // needs binding for §6.5 reverse-resolution
        "cd" => dispatch_with_path_arg("cd", &args, &[0], binding, |a| {
            verbs::cd(shell, a, binding, sink)
        }),
        "ls" => dispatch_with_path_arg("ls", &args, &[0], binding, |a| {
            verbs::ls(shell, a, binding)
        }),
        "cat" => dispatch_with_path_arg("cat", &args, &[0], binding, |a| {
            verbs::cat(shell, a, binding)
        }),
        "tree" => verbs::tree(shell, &args, binding), // flag-style args; alias resolution stays in verb-parser pending parametric dispatch
        "info" => verbs::info(shell, &args, binding), // no path args
        "disconnect" => dispatch_with_identifier_arg("disconnect", &args, &[0], binding, |a| {
            verbs::disconnect(shell, a, binding)
        }),
        "connect" => verbs::connect(shell, &args, binding, spawn), // address arg is literal — no alias expansion
        "exec" => dispatch_with_path_arg("exec", &args, &[0], binding, |a| {
            verbs::exec(shell, a, binding, spawn)
        }),
        "put" => dispatch_with_path_arg("put", &args, &[0], binding, |a| {
            verbs::put(shell, a, binding)
        }),
        "rm" | "remove" => dispatch_with_path_arg("rm", &args, &[0], binding, |a| {
            verbs::rm(shell, a, binding)
        }),
        "query" => verbs::query(&args, binding, spawn), // type-filter arg, no path → no dispatcher-tier alias expansion
        "count" => verbs::count(&args, binding, spawn), // type-filter arg, no path → no dispatcher-tier alias expansion
        "peer" | "peers" => verbs::peer(&args, binding, action_sink),
        "open" => verbs::open(&args, binding, action_sink),
        "tail" => dispatch_with_path_arg("tail", &args, &[0], binding, |a| {
            verbs::tail(shell, a, binding, action_sink)
        }),
        "tails" => verbs::tails(action_sink),
        "untail" => verbs::untail(&args, action_sink),
        // `compute eval/install/uninstall/show` carry a path arg, but
        // it's at position 1 (after the subcommand) — the dispatcher-tier
        // `dispatch_with_path_arg` helper assumes position 0. Alias
        // expansion for compute path args, when needed, lives in the
        // embedding's `compute_*` impl (same pattern as `exec`).
        "compute" => verbs::compute(shell, &args, binding, spawn),
        // `bootstrap import <hex>` carries a literal hex string, not a
        // tree path — no alias expansion. Subcommand-form routing in
        // the verb itself.
        "bootstrap" => verbs::bootstrap(shell, &args, binding, spawn),
        // `inspect chain/under/errors` are pure substrate reads — no
        // dispatched ops, no async. Path args (for `inspect under`)
        // get alias expansion within the verb-parser via `path::resolve`,
        // matching `cat` / `ls` / `tree` rather than the dispatcher-tier
        // helper (the subcommand sits at position 0, not the path).
        "inspect" => verbs::inspect(shell, &args, binding, action_sink),
        _ => return None,
    };
    Some(result)
}

/// Dispatcher-tier alias expansion for verbs whose path args are at
/// known positional indices (guide §8.1 pin: alias resolution happens
/// at the dispatcher tier; verb-parsers receive already-expanded args;
/// verb-ops are alias-unaware by construction).
///
/// Returns an owned `Vec<String>` where the args at `positions` have
/// been alias-expanded. Args outside `positions` are pass-through.
/// Positions beyond `args.len()` are silently skipped (the verb-parser
/// produces a usage error for missing args).
///
/// Errors from `alias::expand` are wrapped as `Result::error` (NotFound
/// code) with `<verb>:` prefix matching the existing message
/// conventions.
fn expand_path_args_at(
    verb: &str,
    args: &[&str],
    positions: &[usize],
    binding: &dyn PeerBinding,
) -> Result<Vec<String>, ShellError> {
    let mut owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    for &pos in positions {
        if pos < owned.len() {
            let expanded = alias::expand(&owned[pos], binding)
                .map_err(|msg| ShellError::not_found(format!("{}: {}", verb, msg)))?;
            owned[pos] = expanded;
        }
    }
    Ok(owned)
}

/// Dispatcher-tier alias expansion for verbs whose args are bare
/// **identifier-typed** (per guide §6.2 standalone-`@alias` usage:
/// `peer delete @foo`, `open Shell @primary`, `disconnect @bob`).
/// Identifier-form expansion produces a bare peer-id (e.g.,
/// `alice_pid`), not a path (`/alice_pid/`). Rejects `@alias/...`
/// path-forms in identifier position as a usage error.
///
/// Returns an owned `Vec<String>` where the args at `positions` have
/// been identifier-expanded; args outside `positions` are pass-through.
fn expand_identifier_args_at(
    verb: &str,
    args: &[&str],
    positions: &[usize],
    binding: &dyn PeerBinding,
) -> Result<Vec<String>, ShellError> {
    let mut owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    for &pos in positions {
        if pos < owned.len() {
            let expanded = alias::resolve_pid(&owned[pos], binding)
                .map_err(|msg| ShellError::not_found(format!("{}: {}", verb, msg)))?;
            owned[pos] = expanded;
        }
    }
    Ok(owned)
}

/// Dispatch helper for verbs whose path arg is at known positional
/// index(es). Mirrors `expand_path_args_at` but for identifier-typed
/// args via `alias::resolve_pid`.
fn dispatch_with_identifier_arg<F>(
    verb: &str,
    args: &[&str],
    positions: &[usize],
    binding: &dyn PeerBinding,
    call: F,
) -> Result<VerbOutput, ShellError>
where
    F: FnOnce(&[&str]) -> Result<VerbOutput, ShellError>,
{
    let owned = expand_identifier_args_at(verb, args, positions, binding)?;
    let arg_refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    call(&arg_refs)
}

/// Dispatch helper for verbs whose only path arg is at position 0 and
/// is optional. `ls`, `tree`, `cat`, `rm`, `put`, `info` shape.
///
/// Note: `tree` is NOT routed through this helper today because its
/// path arg position is not statically known (flag-style args:
/// `tree --depth 2 /path` puts the path at position 2). The
/// dispatcher-tier-resolution pin (§8.1) is awkward for flag-style
/// verbs without a parameter schema; `tree` keeps its in-verb alias
/// expansion until the parametric dispatch shape (§5.2 future) lands.
/// Logged as build-time feedback.
fn dispatch_with_path_arg<F>(
    verb: &str,
    args: &[&str],
    positions: &[usize],
    binding: &dyn PeerBinding,
    call: F,
) -> Result<VerbOutput, ShellError>
where
    F: FnOnce(&[&str]) -> Result<VerbOutput, ShellError>,
{
    let owned = expand_path_args_at(verb, args, positions, binding)?;
    let arg_refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    call(&arg_refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};

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

    #[test]
    fn parse_splits_verb_and_args() {
        assert_eq!(parse("pwd").unwrap(), ("pwd", vec![]));
        assert_eq!(parse("cd /alice/system").unwrap(), ("cd", vec!["/alice/system"]));
        assert_eq!(parse("  cd  /alice/  ").unwrap(), ("cd", vec!["/alice/"]));
        assert_eq!(parse("tree --depth 2").unwrap(), ("tree", vec!["--depth", "2"]));
        assert!(parse("").is_none());
        assert!(parse("   ").is_none());
    }

    #[test]
    fn handles_reports_known_verb_membership() {
        assert!(handles("pwd"));
        assert!(handles("connect"));
        assert!(handles("query"));
        assert!(handles("put"));
        assert!(handles("peer"));
        assert!(handles("open"));
        assert!(handles("tail"));
        assert!(!handles("nonexistent"));
        assert!(!handles("clear"));  // UI op, not a verb
    }

    #[test]
    fn dispatch_routes_pwd() {
        let mut shell = Shell::with_wd("alice", "/alice/system/");
        let result = dispatch("pwd", &mut shell, &StubBinding, None, &(), |_| {}).unwrap();
        assert!(matches!(result, Ok(VerbOutput::Path(ref p)) if p == "/alice/system/"));
    }

    #[test]
    fn dispatch_routes_cd_with_mutation() {
        let mut shell = Shell::with_wd("alice", "/alice/");
        let _ = dispatch("cd system", &mut shell, &StubBinding, None, &(), |_| {}).unwrap();
        assert_eq!(shell.wd(), "/alice/system");
    }

    #[test]
    fn unknown_verb_returns_none() {
        let mut shell = Shell::with_wd("alice", "/alice/");
        let result = dispatch("not-a-real-verb", &mut shell, &StubBinding, None, &(), |_| {});
        assert!(result.is_none());
    }

    #[test]
    fn empty_line_returns_none() {
        let mut shell = Shell::with_wd("alice", "/alice/");
        assert!(dispatch("", &mut shell, &StubBinding, None, &(), |_| {}).is_none());
        assert!(dispatch("   ", &mut shell, &StubBinding, None, &(), |_| {}).is_none());
    }

    #[test]
    fn known_verb_with_bad_args_returns_some_err() {
        let mut shell = Shell::with_wd("alice", "/alice/");
        let result = dispatch("cat", &mut shell, &StubBinding, None, &(), |_| {}).unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, crate::result::ErrorCode::Usage);
    }
}
