//! `help` — verb cheatsheet.
//!
//! Static info rows. Text is canonical English; renderers display
//! as-is per the `VerbOutput::Info` display contract (`result.rs`).
//! Embeddings wanting localized help override this verb in their own
//! dispatcher.
//!
//! Verb-op-shaped by construction (no `Shell`, no binding, no path
//! args → no parser/op seam to factor; the existing function is the
//! op). Guide §8.1 permits this — "the function call between them is
//! the seam," and `help` has no call to factor.
//!
//! **Maintenance:** the verb list below is hand-mirrored against
//! `dispatcher::VERBS`. A unit test asserts every entry in `VERBS`
//! has a help row so the two stay in sync at build time.

use crate::result::{InfoRow, ShellError, VerbOutput};

/// Return the verb cheatsheet as `Info` text rows. Sections grouped:
/// navigation / inspection / writes / handlers / lifecycle / live
/// subscriptions / connection / session.
pub fn help(_args: &[&str]) -> Result<VerbOutput, ShellError> {
    let lines = [
        "All tree ops operate on the BOUND peer's tree (this window).",
        "To inspect another peer, open a new shell bound to it.",
        "",
        "Navigation:",
        "  pwd                          Print the current working directory.",
        "  cd <path>                    Navigate within the tree. Absolute, relative, or @alias[/...].",
        "  ls [path]                    List children under path (or wd).",
        "",
        "Inspection:",
        "  cat <path>                   Show the entity at path.",
        "  tree [path] [--depth N]      Recursive listing under path.",
        "  query <type-filter> [limit]  Find entities by type. Streaming.",
        "  count <type-filter>          Count entities by type.",
        "  info                         Show bound peer, primary, arm, counts, wd.",
        "",
        "Writes:",
        "  put <path> <type> [<json>]   Store an entity (parsed JSON body, or null).",
        "  rm <path>                    Remove the entity at path.",
        "",
        "Handlers:",
        "  exec <handler-uri> <op> [<json>]   Execute a handler operation. Streaming.",
        "",
        "Peer lifecycle (queues an app-level action):",
        "  peer list                    Show local + remote peers.",
        "  peer create <mode> [label]   mode: frontend | memory | opfs",
        "  peer delete <peer>           Delete a backend peer (refuses primary).",
        "  peer rename <peer> <label>   Set or clear a peer label.",
        "  peers                        Alias for `peer list`.",
        "",
        "Connection:",
        "  connect <address>            Open a connection. Schemes: ws:// wss:// memory:// xworker://",
        "  disconnect <peer>            Close a remote connection.",
        "",
        "Live subscriptions:",
        "  tail <prefix>                Stream tree change events under prefix.",
        "  tails                        List active tail subscriptions.",
        "  untail <prefix|all>          Stop a tail (or all).",
        "",
        "Identity:",
        "  bootstrap [--threshold N] [--label X]   Bootstrap this peer's identity stack (1-of-1 default).",
        "  bootstrap status                         Show whether bootstrap is complete.",
        "  bootstrap export                         Export identity as a portable CBOR bundle (hex).",
        "  bootstrap import <hex>                   Restore identity from a previously-exported bundle.",
        "",
        "Compute:",
        "  compute eval <expr-path> [--budget N]            Evaluate the expression at this tree path.",
        "  compute install <root-path> [--result-path P]    Install a reactive subgraph rooted here.",
        "  compute uninstall <subgraph-path>                Remove an installed subgraph.",
        "  compute list                                     List installed subgraphs.",
        "  compute show <subgraph-path>                     Show one subgraph's metadata.",
        "",
        "Windows + session:",
        "  open <window-type> [@peer]   Spawn a new window (bound to peer if given).",
        "  clear                        Wipe the scrollback (or press Ctrl-L).",
        "  help                         This list.",
        "",
        "Aliases: @self (bound peer)  @primary / @system / @default (primary peer)",
        "  @<label>                   Resolves to the peer with matching label.",
        "  @<pid-prefix>              Resolves to the peer whose id starts with prefix.",
    ];
    Ok(VerbOutput::Info(
        lines.into_iter().map(InfoRow::text).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::VERBS;

    #[test]
    fn returns_info_rows() {
        match help(&[]).unwrap() {
            VerbOutput::Info(rows) => {
                assert!(rows.len() > 20);
                assert!(rows.iter().any(|r| r.value.contains("pwd")));
                assert!(rows.iter().any(|r| r.value.contains("cd")));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    /// Build-time gate: every verb in the dispatcher's `VERBS` table
    /// must have a help row. Catches drift between the dispatcher
    /// and the cheatsheet — the failure mode this test guards against
    /// is exactly the one shipped earlier (8 of 18 verbs
    /// listed; users had no way to discover the rest).
    #[test]
    fn help_covers_every_dispatched_verb() {
        let VerbOutput::Info(rows) = help(&[]).unwrap() else {
            panic!("help must return Info");
        };
        let text: String = rows
            .iter()
            .map(|r| r.value.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for verb in VERBS {
            // `peers` is documented as an alias under `peer list`;
            // skip its standalone check.
            if *verb == "peers" {
                assert!(text.contains("peers"), "help missing peers alias");
                continue;
            }
            assert!(
                text.contains(verb),
                "help text does not mention dispatched verb `{}` — \
                 update `bindings/shell/src/verbs/help.rs` to match \
                 `dispatcher::VERBS`",
                verb
            );
        }
    }
}
