//! `tree [<path>] [--depth N]` — recursive listing per guide §4.1.
//!
//! DFS walk against `PeerBinding::tree_listing`. Default depth bounded
//! at 100 levels (effectively unlimited for typical trees) to prevent
//! runaway recursion on cyclic / pathological inputs. `--depth 0` is
//! treated as "no descent" (only the prefix's immediate children at
//! depth 1).
//!
//! Factored per guide §8.1 four-layer model: `tree_op` is the typed
//! verb-op (reusable by non-shell consumers); `tree` is the verb-
//! parser that resolves args against shell state and calls the op.
//! Alias expansion happens in the parser tier here (not the
//! dispatcher) — the path positional is optional, so static
//! dispatcher metadata can't single out a position to pre-resolve.

use crate::alias;
use crate::binding::PeerBinding;
use crate::path;
use crate::result::{ShellError, TreeEntry, TreeView, VerbOutput};
use crate::shell::Shell;

/// Verb-op (§8.1). DFS walk under `prefix` (an absolute path —
/// already alias-expanded and wd-resolved by the verb-parser) with an
/// optional depth bound (`None` → default cap 100, `Some(0)` → no
/// descent). Reusable from non-shell consumers (panels, palettes)
/// without going through the verb-parser.
pub fn tree_op(
    binding: &dyn PeerBinding,
    prefix: &str,
    depth_limit: Option<usize>,
) -> Result<VerbOutput, ShellError> {
    let cap = depth_limit.unwrap_or(100);
    let mut entries = Vec::new();
    walk(binding, prefix, 0, cap, &mut entries);
    Ok(VerbOutput::Tree(TreeView {
        root: prefix.to_string(),
        depth_limit,
        entries,
    }))
}

/// Verb-parser (§8.1). Parses `[<path>] [--depth N]`, alias-expands
/// the optional path arg, resolves against the shell's working
/// directory, and calls `tree_op`.
pub fn tree(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let (path_arg, depth_limit) = parse_args(args)?;
    let prefix = match path_arg {
        Some(t) => {
            let expanded = alias::expand(t, binding)
                .map_err(|msg| ShellError::not_found(format!("tree: {}", msg)))?;
            path::resolve(shell.wd(), &expanded)
        }
        None => shell.wd().to_string(),
    };
    tree_op(binding, &prefix, depth_limit)
}

/// Parse `tree`'s argument list: optional path positional + optional
/// `--depth N` flag. Order-independent.
fn parse_args<'a>(args: &'a [&'a str]) -> Result<(Option<&'a str>, Option<usize>), ShellError> {
    let mut path = None;
    let mut depth = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--depth" => {
                if i + 1 >= args.len() {
                    return Err(ShellError::usage("tree: --depth requires a number"));
                }
                let n: usize = args[i + 1].parse().map_err(|_| {
                    ShellError::usage(format!(
                        "tree: --depth: invalid number '{}'",
                        args[i + 1]
                    ))
                })?;
                depth = Some(n);
                i += 2;
            }
            arg if !arg.starts_with("--") => {
                if path.is_some() {
                    return Err(ShellError::usage(format!(
                        "tree: unexpected arg '{}'",
                        arg
                    )));
                }
                path = Some(arg);
                i += 1;
            }
            _ => {
                return Err(ShellError::usage(format!(
                    "tree: unknown flag '{}'",
                    args[i]
                )));
            }
        }
    }
    Ok((path, depth))
}

/// Depth-bounded recursive walk. Yielded depths are 1-based — direct
/// children of `prefix` are depth 1.
fn walk(
    binding: &dyn PeerBinding,
    prefix: &str,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<TreeEntry>,
) {
    if depth >= max_depth {
        return;
    }
    let entries = binding.tree_listing(binding.peer_id(), prefix);
    for e in entries {
        out.push(TreeEntry {
            path: e.path.clone(),
            depth: depth + 1,
        });
        let mut subprefix = e.path;
        if !subprefix.ends_with('/') {
            subprefix.push('/');
        }
        walk(binding, &subprefix, depth + 1, max_depth, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};

    /// Stub returning hardcoded children per prefix.
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
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }
    }

    fn entry(path: &str) -> TreeListingEntry {
        TreeListingEntry { path: path.into() }
    }

    fn tree_stub() -> StubBinding {
        // Shape:
        //   /alice/  → [system, app]
        //   /alice/system/ → [identity]
        //   /alice/app/ → [foo]
        StubBinding {
            bound: "alice".into(),
            listing: vec![
                ("/alice/".into(), vec![entry("/alice/system"), entry("/alice/app")]),
                ("/alice/system/".into(), vec![entry("/alice/system/identity")]),
                ("/alice/app/".into(), vec![entry("/alice/app/foo")]),
            ],
        }
    }

    #[test]
    fn dfs_order_with_default_depth() {
        let b = tree_stub();
        let shell = Shell::with_wd("alice", "/alice/");
        match tree(&shell, &[], &b).unwrap() {
            VerbOutput::Tree(view) => {
                assert_eq!(view.root, "/alice/");
                let paths: Vec<&str> = view.entries.iter().map(|e| e.path.as_str()).collect();
                assert_eq!(
                    paths,
                    vec![
                        "/alice/system",
                        "/alice/system/identity",
                        "/alice/app",
                        "/alice/app/foo",
                    ]
                );
                // Direct children at depth 1, grandchildren at depth 2.
                assert_eq!(view.entries[0].depth, 1);
                assert_eq!(view.entries[1].depth, 2);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn depth_one_yields_only_immediate_children() {
        let b = tree_stub();
        let shell = Shell::with_wd("alice", "/alice/");
        match tree(&shell, &["--depth", "1"], &b).unwrap() {
            VerbOutput::Tree(view) => {
                let paths: Vec<&str> = view.entries.iter().map(|e| e.path.as_str()).collect();
                assert_eq!(paths, vec!["/alice/system", "/alice/app"]);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn depth_zero_yields_nothing() {
        let b = tree_stub();
        let shell = Shell::with_wd("alice", "/alice/");
        match tree(&shell, &["--depth", "0"], &b).unwrap() {
            VerbOutput::Tree(view) => assert!(view.entries.is_empty()),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn invalid_depth_returns_usage() {
        let b = tree_stub();
        let shell = Shell::with_wd("alice", "/alice/");
        let err = tree(&shell, &["--depth", "abc"], &b).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn unknown_flag_returns_usage() {
        let b = tree_stub();
        let shell = Shell::with_wd("alice", "/alice/");
        let err = tree(&shell, &["--bogus"], &b).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn tree_op_walks_resolved_prefix_with_default_cap() {
        let b = tree_stub();
        match tree_op(&b, "/alice/", None).unwrap() {
            VerbOutput::Tree(view) => {
                assert_eq!(view.root, "/alice/");
                assert_eq!(view.depth_limit, None);
                let paths: Vec<&str> = view.entries.iter().map(|e| e.path.as_str()).collect();
                assert_eq!(
                    paths,
                    vec![
                        "/alice/system",
                        "/alice/system/identity",
                        "/alice/app",
                        "/alice/app/foo",
                    ]
                );
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn tree_op_respects_depth_zero() {
        let b = tree_stub();
        match tree_op(&b, "/alice/", Some(0)).unwrap() {
            VerbOutput::Tree(view) => assert!(view.entries.is_empty()),
            other => panic!("unexpected variant: {:?}", other),
        }
    }
}
