//! `inspect <chain|under|errors|help>` — inspectability verbs.
//!
//! Per `GUIDE-INSPECTABILITY.md` v1.2 §2.4 projection table: chain
//! trace, entity reader, and path enumerator are derived capabilities
//! that compose from pure substrate reads — no L1 event hooks
//! required. These three verbs surface that observation in the shell.
//!
//! - `inspect chain <chain_id>` — walk continuation entities +
//!   chain-error markers attributed to the chain on the bound peer.
//!   Composes path-enumerator (filtered by `/system/continuation/` +
//!   `/system/runtime/chain-errors/` prefixes) and entity-reader (for
//!   the matched paths).
//! - `inspect under <prefix>` — list every binding under the prefix
//!   on the bound peer. Path-enumerator primitive.
//! - `inspect errors` — enumerate all chain-error markers on the
//!   bound peer, grouped by chain_id. Subset of `inspect under` with
//!   marker-shape parsing.
//!
//! - `inspect entity <path>` — read the entity at `path` and render
//!   path / type / hash / len / CBOR-pretty-print of the body.
//!   Entity-reader primitive.
//! - `inspect dump <hash>` — look up by content hash and render the
//!   same shape as `entity`. `--paths` flag (default off) enumerates
//!   paths that reference this hash (cost: O(N) tree walk).
//! - `inspect find <substring>` — substring search over every path on
//!   the bound peer. `--limit N` cap (default 200).
//!
//! - `inspect tap` — open a live dispatch-event view (Path Tap window)
//!   for the bound peer. Shorthand for `open Path Tap`; the embedding
//!   resolves the window-type name and spawns it. Per Dom's Tier-2 #4
//!   from the inspect-worker-arm handoff.
//!
//! Sub-ops `content`, `wire`, `watch` may follow as embedding-side
//! sibling windows ship (Content Stream + Wire Recorder shipped
//! on the egui side and are openable via bare `open` until
//! dedicated shortcut verbs land).
//!
//! Renderer policy (`AUDIT-PRIVACY-AND-CROSS-PEER §2.5`): the
//! continuation + chain-error families are `capability-controlled` —
//! shell consumers in operator mode (the default for entity-shell as
//! a developer surface) surface entity bodies; non-operator consumers
//! should redact. Shell renders the path/type; the embedding decides
//! whether to surface the body. Per `feedback_sdk_is_the_substrate`
//! the policy lookup belongs in the SDK / renderer, not in the verb.

use crate::action::{AppActionSink, ShellRequest};
use crate::binding::PeerBinding;
use crate::format;
use crate::path;
use crate::result::{InfoRow, ListingSection, ShellError, VerbOutput};
use crate::shell::Shell;

/// Default cap on `inspect find` results to avoid dumping thousands of
/// rows into the shell for one-character substrings. Override via
/// `--limit N`.
const FIND_DEFAULT_LIMIT: usize = 200;

/// Verb-parser (§8.1). Top-level sub-op router for inspect.
pub fn inspect(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    action_sink: &dyn AppActionSink,
) -> Result<VerbOutput, ShellError> {
    let (sub, rest) = args.split_first().ok_or_else(|| {
        ShellError::usage(
            "inspect: usage: inspect <chain|under|errors|entity|dump|find|tap|help> [args...]",
        )
    })?;
    match *sub {
        "chain" => chain(shell, rest, binding),
        "under" => under(shell, rest, binding),
        "errors" => Ok(errors_op(shell.peer_id(), binding)),
        "entity" => entity(shell, rest, binding),
        "dump" => dump(shell, rest, binding),
        "find" => find(shell, rest, binding),
        "tap" => Ok(tap_op(shell.peer_id(), action_sink)),
        "help" => Ok(help_op()),
        other => Err(ShellError::unknown(format!(
            "inspect: unknown subcommand '{}'. Try: chain, under, errors, entity, dump, find, tap, help.",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// inspect tap
//
// Shorthand for `open Path Tap` — surfaces the live dispatch-event
// view the embedding's Path Tap window renders. Per Dom's Tier-2 #4
// from the inspect-worker-arm handoff: dedicated verb shortcut so users don't
// need to remember the full window name (and the catalog lookup) for
// a frequently-used diagnostic.
//
// Submits the SpawnWindow request and returns an Info row confirming
// the action. The embedding is responsible for whether the window
// type is actually registered — if not, our error path (`open` already
// does this) reads from `available_windows`, but for the shortcut we
// fire-and-confirm; the embedding's window manager logs / rejects if
// the name is unknown. Same posture as `tail` / `untail`.
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Submit a `SpawnWindow { type_name: "Path Tap" }`
/// against the bound peer.
fn tap_op(peer_id: &str, action_sink: &dyn AppActionSink) -> VerbOutput {
    action_sink.submit(ShellRequest::SpawnWindow {
        type_name: "Path Tap".to_string(),
        peer_id: Some(peer_id.to_string()),
    });
    VerbOutput::Info(vec![InfoRow::text(format!(
        "→ opening Path Tap on {}",
        crate::display::short_pid(peer_id),
    ))])
}

// ---------------------------------------------------------------------------
// inspect chain <chain_id>
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Walk the substrate state attributed to `chain_id`
/// on `peer_id` — continuation entities at
/// `/{peer_id}/system/continuation/{chain_id}` and chain-error markers
/// at `/{peer_id}/system/runtime/chain-errors/{lost|rejected}/{chain_id}/...`.
/// Returns a `Listing` with two sections: Continuations + Markers.
pub fn chain_op(
    binding: &dyn PeerBinding,
    peer_id: &str,
    chain_id: &str,
) -> VerbOutput {
    let continuation_prefix = format!("/{peer_id}/system/continuation/");
    let chain_errors_prefix = format!("/{peer_id}/system/runtime/chain-errors/");

    let continuations: Vec<String> = binding
        .tree_listing(peer_id, &continuation_prefix)
        .into_iter()
        .filter_map(|e| {
            continuation_chain_id(&e.path)
                .map(|c| c.to_string())
                .filter(|c| c == chain_id)
                .map(|_| format_entry_row(&e.path, binding, peer_id))
        })
        .collect();

    let markers: Vec<String> = binding
        .tree_listing(peer_id, &chain_errors_prefix)
        .into_iter()
        .filter_map(|e| {
            let cid = marker_chain_id(&e.path)?;
            if cid != chain_id {
                return None;
            }
            let (kind, reason) = marker_kind_reason(&e.path);
            Some(format!(
                "[{kind}] reason={reason} · {}",
                format_entry_row(&e.path, binding, peer_id),
            ))
        })
        .collect();

    if continuations.is_empty() && markers.is_empty() {
        return VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                format!("inspect chain {chain_id}"),
                vec![format!(
                    "(no continuation or chain-error marker bound on peer {peer_id})",
                )],
            )],
        };
    }

    let mut sections = Vec::new();
    if !continuations.is_empty() {
        sections.push(ListingSection::with_header(
            format!("Continuations ({})", continuations.len()),
            continuations,
        ));
    }
    if !markers.is_empty() {
        sections.push(ListingSection::with_header(
            format!("Chain-error markers ({})", markers.len()),
            markers,
        ));
    }
    VerbOutput::Listing { sections }
}

fn chain(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let chain_id = args
        .first()
        .ok_or_else(|| ShellError::usage("inspect chain: missing chain_id argument"))?;
    Ok(chain_op(binding, shell.peer_id(), chain_id))
}

// ---------------------------------------------------------------------------
// inspect under <prefix>
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Enumerate every binding under `prefix` on
/// `peer_id`. Pure path-enumerator primitive (v1.2 §2.2). Aliases
/// already expanded at dispatcher tier.
pub fn under_op(
    binding: &dyn PeerBinding,
    peer_id: &str,
    prefix: &str,
) -> VerbOutput {
    let entries = binding
        .tree_listing(peer_id, prefix)
        .into_iter()
        .map(|e| e.path)
        .collect::<Vec<_>>();

    if entries.is_empty() {
        return VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                format!("inspect under {prefix}"),
                vec!["(no bindings)".to_string()],
            )],
        };
    }

    VerbOutput::Listing {
        sections: vec![ListingSection::with_header(
            format!("inspect under {prefix} — {} bindings", entries.len()),
            entries,
        )],
    }
}

fn under(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let prefix_arg = args
        .first()
        .ok_or_else(|| ShellError::usage("inspect under: missing prefix argument"))?;
    let resolved = path::resolve(shell.wd(), prefix_arg);
    Ok(under_op(binding, shell.peer_id(), &resolved))
}

// ---------------------------------------------------------------------------
// inspect errors
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Enumerate all chain-error markers on the bound
/// peer, grouped by chain_id. Each entry is one marker; entries
/// within a group are in lexicographic (≈ step) order.
pub fn errors_op(peer_id: &str, binding: &dyn PeerBinding) -> VerbOutput {
    let prefix = format!("/{peer_id}/system/runtime/chain-errors/");
    let mut paths: Vec<String> = binding
        .tree_listing(peer_id, &prefix)
        .into_iter()
        .map(|e| e.path)
        .collect();
    paths.sort();

    if paths.is_empty() {
        return VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                "inspect errors",
                vec![format!("(no chain-error markers on peer {peer_id})")],
            )],
        };
    }

    // Group by chain_id (segment 5 of the marker path).
    use std::collections::BTreeMap;
    let mut by_chain: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in paths {
        let chain_id = marker_chain_id(&p).map(String::from).unwrap_or_else(|| "?".into());
        let (kind, reason) = marker_kind_reason(&p);
        by_chain
            .entry(chain_id)
            .or_default()
            .push(format!("[{kind}] reason={reason} · {p}"));
    }

    let sections = by_chain
        .into_iter()
        .map(|(chain_id, rows)| ListingSection::with_header(format!("chain {chain_id}"), rows))
        .collect();
    VerbOutput::Listing { sections }
}

// ---------------------------------------------------------------------------
// inspect entity <path>
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Read the entity at `path` on `peer_id` and render
/// path / type / hash / len header + CBOR-pretty-printed body.
/// Entity-reader primitive (v1.2 §2.2).
pub fn entity_op(
    binding: &dyn PeerBinding,
    peer_id: &str,
    path: &str,
) -> VerbOutput {
    match binding.get_entity(peer_id, path) {
        Some(entity) => VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                format!("entity {path}"),
                render_entity_dump_rows(path, &entity),
            )],
        },
        None => VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                format!("entity {path}"),
                vec![format!("(no entity at {path} on peer {peer_id})")],
            )],
        },
    }
}

fn entity(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let path_arg = args
        .first()
        .ok_or_else(|| ShellError::usage("inspect entity: missing path argument"))?;
    let resolved = path::resolve(shell.wd(), path_arg);
    Ok(entity_op(binding, shell.peer_id(), &resolved))
}

// ---------------------------------------------------------------------------
// inspect dump <hash> [--paths]
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Look up the entity by content `hash_hex` on
/// `peer_id` and render its body. When `with_paths` is true, walk the
/// tree to enumerate every path that binds to this hash (O(N) — opt-in
/// via `--paths`).
pub fn dump_op(
    binding: &dyn PeerBinding,
    peer_id: &str,
    hash_hex: &str,
    with_paths: bool,
) -> VerbOutput {
    let Some(entity) = binding.get_entity_by_hash(peer_id, hash_hex) else {
        return VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                format!("dump {hash_hex}"),
                vec![format!(
                    "(no entity with hash {hash_hex} reachable from peer {peer_id})"
                )],
            )],
        };
    };

    // Header section: path-list placeholder (the entity may be bound at
    // multiple paths, or none directly; render hash-keyed lookup result).
    let mut sections = vec![ListingSection::with_header(
        format!("dump {hash_hex}"),
        render_entity_dump_rows("(hash-keyed)", &entity),
    )];

    if with_paths {
        let paths: Vec<String> = binding
            .tree_listing(peer_id, &format!("/{peer_id}/"))
            .into_iter()
            .filter_map(|e| {
                binding
                    .get_entity(peer_id, &e.path)
                    .filter(|read| read.content_hash == hash_hex)
                    .map(|_| e.path)
            })
            .collect();
        let rows = if paths.is_empty() {
            vec![format!(
                "(hash present in store but no path binding found on peer {peer_id})"
            )]
        } else {
            paths
        };
        sections.push(ListingSection::with_header(
            format!("paths referencing this hash ({})", rows.len()),
            rows,
        ));
    }

    VerbOutput::Listing { sections }
}

fn dump(
    _shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let mut hash_hex: Option<&str> = None;
    let mut with_paths = false;
    for arg in args {
        match *arg {
            "--paths" => with_paths = true,
            other => {
                if hash_hex.is_some() {
                    return Err(ShellError::usage(format!(
                        "inspect dump: unexpected extra argument '{other}'. Usage: inspect dump <hash-hex> [--paths]",
                    )));
                }
                hash_hex = Some(other);
            }
        }
    }
    let hash_hex = hash_hex.ok_or_else(|| {
        ShellError::usage("inspect dump: missing <hash-hex> argument")
    })?;
    if hash_hex.is_empty() || !hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ShellError::usage(format!(
            "inspect dump: hash must be a non-empty hex string (got '{hash_hex}')",
        )));
    }
    Ok(dump_op(binding, _shell.peer_id(), hash_hex, with_paths))
}

// ---------------------------------------------------------------------------
// inspect find <substring> [--limit N]
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Enumerate every binding on `peer_id` whose path
/// contains `substring`. Bounded by `limit` (default 200) so a
/// one-character substring doesn't flood the shell scrollback. Pure
/// post-filter over `tree_listing` — no kernel surface.
pub fn find_op(
    binding: &dyn PeerBinding,
    peer_id: &str,
    substring: &str,
    limit: usize,
) -> VerbOutput {
    let all: Vec<String> = binding
        .tree_listing(peer_id, &format!("/{peer_id}/"))
        .into_iter()
        .filter_map(|e| e.path.contains(substring).then_some(e.path))
        .collect();

    let total = all.len();
    if total == 0 {
        return VerbOutput::Listing {
            sections: vec![ListingSection::with_header(
                format!("inspect find \"{substring}\""),
                vec![format!("(no matches on peer {peer_id})")],
            )],
        };
    }

    let truncated = total > limit;
    let mut entries: Vec<String> = all.into_iter().take(limit).collect();
    if truncated {
        entries.push(format!(
            "… {} more (raise with --limit N)",
            total - limit
        ));
    }

    VerbOutput::Listing {
        sections: vec![ListingSection::with_header(
            format!(
                "inspect find \"{substring}\" — {} {}",
                if truncated { limit } else { total },
                if truncated {
                    format!("of {total} matches")
                } else {
                    "matches".to_string()
                },
            ),
            entries,
        )],
    }
}

fn find(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    let mut substring: Option<&str> = None;
    let mut limit: usize = FIND_DEFAULT_LIMIT;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--limit" => {
                let n_arg = args.get(i + 1).ok_or_else(|| {
                    ShellError::usage("inspect find: --limit requires a positive integer")
                })?;
                limit = n_arg.parse::<usize>().map_err(|_| {
                    ShellError::usage(format!(
                        "inspect find: --limit expects a positive integer (got '{n_arg}')",
                    ))
                })?;
                if limit == 0 {
                    return Err(ShellError::usage("inspect find: --limit must be > 0"));
                }
                i += 2;
            }
            other => {
                if substring.is_some() {
                    return Err(ShellError::usage(format!(
                        "inspect find: unexpected extra argument '{other}'. Usage: inspect find <substring> [--limit N]",
                    )));
                }
                substring = Some(other);
                i += 1;
            }
        }
    }
    let substring = substring.ok_or_else(|| {
        ShellError::usage("inspect find: missing <substring> argument")
    })?;
    if substring.is_empty() {
        return Err(ShellError::usage(
            "inspect find: substring must be non-empty (refusing to match everything)",
        ));
    }
    Ok(find_op(binding, shell.peer_id(), substring, limit))
}

/// Build the "path / type / hash / len / data" rows for an entity
/// dump. Shared between `entity_op` and `dump_op` for visual parity.
fn render_entity_dump_rows(path: &str, entity: &crate::binding::EntityRead) -> Vec<String> {
    let mut rows = vec![
        format!("path:  {path}"),
        format!("type:  {}", entity.entity_type),
        format!(
            "hash:  {}",
            if entity.content_hash.is_empty() {
                "(unknown)".to_string()
            } else {
                entity.content_hash.clone()
            },
        ),
        format!("len:   {} bytes", entity.data.len()),
        String::new(),
        "data:".to_string(),
    ];
    for line in format::entity_data(&entity.data).lines() {
        rows.push(format!("  {line}"));
    }
    rows
}

// ---------------------------------------------------------------------------
// inspect help
// ---------------------------------------------------------------------------

fn help_op() -> VerbOutput {
    let lines = vec![
        "inspect — surface entity-system observability through pure substrate reads.",
        "",
        "Usage:",
        "  inspect chain <chain_id>           walk continuations + chain-error markers for a chain",
        "  inspect under <prefix>             list every binding under a prefix",
        "  inspect errors                     enumerate all chain-error markers, grouped by chain",
        "  inspect entity <path>              read + pretty-print the entity at a path",
        "  inspect dump <hash> [--paths]      look up an entity by content hash",
        "  inspect find <substring> [--limit N]   substring search over paths on the bound peer (default --limit 200)",
        "  inspect tap                        open live dispatch-event view (Path Tap window) for the bound peer",
        "  inspect help                       this message",
        "",
        "Per GUIDE-INSPECTABILITY v1.2 §2.4 projection table: chain/under/errors/entity/dump/find",
        "compose from entity reader + path enumerator primitives (no live event hooks required).",
        "`tap` opens the embedding's Path Tap window — live `InspectFact::Dispatch` stream via",
        "`Peers::install_inspect_sink`. Content / Wire siblings exist as standalone windows",
        "(Content Stream / Wire Recorder), reachable today via bare `open`.",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    VerbOutput::Listing {
        sections: vec![ListingSection::with_header("inspect", lines)],
    }
}

// ---------------------------------------------------------------------------
// Path parsers — match `chain_trace_cache` shape on the consumer side
// ---------------------------------------------------------------------------

/// `/{peer_id}/system/continuation/{chain_id}` → `chain_id` slice.
fn continuation_chain_id(path: &str) -> Option<&str> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segments.len() >= 4 && segments[1] == "system" && segments[2] == "continuation" {
        Some(segments[3])
    } else {
        None
    }
}

/// `/{peer_id}/system/runtime/chain-errors/{lost|rejected}/{chain_id}/...`
/// → `chain_id` slice.
fn marker_chain_id(path: &str) -> Option<&str> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segments.len() >= 6
        && segments[1] == "system"
        && segments[2] == "runtime"
        && segments[3] == "chain-errors"
        && (segments[4] == "lost" || segments[4] == "rejected")
    {
        Some(segments[5])
    } else {
        None
    }
}

/// `(kind, reason)` extracted from the marker path. Empty strings on
/// non-matching shapes.
fn marker_kind_reason(path: &str) -> (String, String) {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // /{peer}/system/runtime/chain-errors/{kind}/{chain}/{step}/{reason}/{hash}
    if segments.len() >= 8
        && segments[1] == "system"
        && segments[2] == "runtime"
        && segments[3] == "chain-errors"
    {
        (segments[4].to_string(), segments[7].to_string())
    } else {
        (String::new(), String::new())
    }
}

/// Format one entry row — path + entity type lookup (`<unread>` when
/// the entity isn't decodable from this binding).
fn format_entry_row(path: &str, binding: &dyn PeerBinding, peer_id: &str) -> String {
    let type_label = binding
        .get_entity(peer_id, path)
        .map(|e| e.entity_type)
        .unwrap_or_else(|| String::from("<unread>"));
    format!("{path} (type={type_label})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};

    struct StubBinding {
        bound: String,
        bindings: Vec<TreeListingEntry>,
        entities: Vec<(String, EntityRead)>,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.bound }
        fn primary_peer_id(&self) -> String { self.bound.clone() }
        fn peer_ids(&self) -> Vec<String> { vec![self.bound.clone()] }
        fn connected_peers(&self) -> Vec<String> { Vec::new() }
        fn peer_label(&self, _pid: &str) -> Option<String> { None }
        fn tree_listing(&self, _pid: &str, prefix: &str) -> Vec<TreeListingEntry> {
            self.bindings
                .iter()
                .filter(|e| e.path.starts_with(prefix))
                .cloned()
                .collect()
        }
        fn get_entity(&self, _pid: &str, path: &str) -> Option<EntityRead> {
            self.entities
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, e)| e.clone())
        }
        fn get_entity_by_hash(&self, _pid: &str, hash_hex: &str) -> Option<EntityRead> {
            self.entities
                .iter()
                .find(|(_, e)| e.content_hash == hash_hex)
                .map(|(_, e)| e.clone())
        }
    }

    fn cbor_text(s: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Text(s.into()), &mut bytes).unwrap();
        bytes
    }

    fn ent(t: &str, body: &str) -> EntityRead {
        EntityRead {
            entity_type: t.to_string(),
            data: body.as_bytes().to_vec(),
            content_hash: String::new(),
        }
    }

    fn make_binding() -> StubBinding {
        StubBinding {
            bound: "PEER1".into(),
            bindings: vec![
                TreeListingEntry {
                    path: "/PEER1/system/continuation/CHAIN_A".into(),
                },
                TreeListingEntry {
                    path: "/PEER1/system/runtime/chain-errors/lost/CHAIN_A/0/timeout/0xabc".into(),
                },
                TreeListingEntry {
                    path: "/PEER1/system/runtime/chain-errors/rejected/CHAIN_A/1/cap_denied/0xdef".into(),
                },
                TreeListingEntry {
                    path: "/PEER1/system/runtime/chain-errors/lost/CHAIN_B/0/timeout/0x111".into(),
                },
                TreeListingEntry {
                    path: "/PEER1/system/continuation/CHAIN_OTHER".into(),
                },
                TreeListingEntry {
                    path: "/PEER1/app/demo/note".into(),
                },
            ],
            entities: vec![
                (
                    "/PEER1/system/continuation/CHAIN_A".into(),
                    ent("system/continuation", "x"),
                ),
                (
                    "/PEER1/system/runtime/chain-errors/lost/CHAIN_A/0/timeout/0xabc".into(),
                    ent("system/runtime/chain-error-lost", "y"),
                ),
            ],
        }
    }

    #[test]
    fn inspect_chain_filters_to_matching_chain_id() {
        let binding = make_binding();
        let output = chain_op(&binding, "PEER1", "CHAIN_A");
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert_eq!(sections.len(), 2, "should have Continuations + Markers");
        // Continuations section: CHAIN_A only.
        let conts = &sections[0];
        assert!(conts.header.as_ref().unwrap().contains("Continuations"));
        assert_eq!(conts.entries.len(), 1);
        assert!(conts.entries[0].contains("CHAIN_A"));
        assert!(!conts.entries[0].contains("CHAIN_OTHER"));
        // Markers section: two markers for CHAIN_A (lost + rejected).
        let markers = &sections[1];
        assert!(markers.header.as_ref().unwrap().contains("Chain-error"));
        assert_eq!(markers.entries.len(), 2);
        assert!(markers.entries.iter().any(|r| r.contains("[lost]")));
        assert!(markers.entries.iter().any(|r| r.contains("[rejected]")));
        // Other chain's marker stays out.
        assert!(!markers.entries.iter().any(|r| r.contains("CHAIN_B")));
    }

    #[test]
    fn inspect_chain_unknown_chain_id_shows_no_bindings_message() {
        let binding = make_binding();
        let output = chain_op(&binding, "PEER1", "NONEXISTENT");
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert_eq!(sections.len(), 1);
        assert!(sections[0].entries[0].contains("no continuation or chain-error"));
    }

    #[test]
    fn inspect_under_lists_bindings_under_prefix() {
        let binding = make_binding();
        let output = under_op(&binding, "PEER1", "/PEER1/system/runtime/chain-errors/");
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert_eq!(sections.len(), 1);
        // Three markers under chain-errors prefix.
        assert_eq!(sections[0].entries.len(), 3);
        for row in &sections[0].entries {
            assert!(row.contains("chain-errors"));
        }
    }

    #[test]
    fn inspect_under_empty_prefix_shows_no_bindings() {
        let binding = make_binding();
        let output = under_op(&binding, "PEER1", "/PEER1/system/nowhere/");
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert_eq!(sections[0].entries, vec!["(no bindings)"]);
    }

    #[test]
    fn inspect_errors_groups_by_chain_id() {
        let binding = make_binding();
        let output = errors_op("PEER1", &binding);
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        // Two groups: CHAIN_A (2 markers) + CHAIN_B (1 marker).
        assert_eq!(sections.len(), 2);
        let chain_a = sections
            .iter()
            .find(|s| s.header.as_ref().unwrap().contains("CHAIN_A"))
            .expect("CHAIN_A group present");
        assert_eq!(chain_a.entries.len(), 2);
        let chain_b = sections
            .iter()
            .find(|s| s.header.as_ref().unwrap().contains("CHAIN_B"))
            .expect("CHAIN_B group present");
        assert_eq!(chain_b.entries.len(), 1);
    }

    #[test]
    fn inspect_errors_no_markers_shows_message() {
        let binding = StubBinding {
            bound: "PEER1".into(),
            bindings: vec![],
            entities: vec![],
        };
        let output = errors_op("PEER1", &binding);
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert!(sections[0].entries[0].contains("no chain-error markers"));
    }

    #[test]
    fn inspect_help_returns_usage() {
        let output = help_op();
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert!(sections[0]
            .entries
            .iter()
            .any(|r| r.contains("inspect chain")));
        // tap shortcut must be discoverable from help.
        assert!(
            sections[0].entries.iter().any(|r| r.contains("inspect tap")),
            "help must list `inspect tap`"
        );
    }

    // -- inspect tap (Dom Tier-2 #4) --

    struct CaptureSink {
        submitted: std::cell::RefCell<Vec<crate::action::ShellRequest>>,
    }
    impl crate::action::AppActionSink for CaptureSink {
        fn submit(&self, request: crate::action::ShellRequest) {
            self.submitted.borrow_mut().push(request);
        }
    }

    #[test]
    fn inspect_tap_submits_spawn_path_tap_on_bound_peer() {
        let sink = CaptureSink {
            submitted: std::cell::RefCell::new(Vec::new()),
        };
        let output = tap_op("PEER1", &sink);

        // Returns an Info row confirming the action.
        match output {
            VerbOutput::Info(rows) => {
                assert_eq!(rows.len(), 1);
                assert!(
                    rows[0].value.contains("Path Tap"),
                    "Info should mention Path Tap; got: {}",
                    rows[0].value
                );
            }
            other => panic!("expected Info, got {:?}", other),
        }

        // Exactly one SpawnWindow submitted, on the bound peer.
        let reqs = sink.submitted.borrow();
        assert_eq!(reqs.len(), 1);
        match &reqs[0] {
            crate::action::ShellRequest::SpawnWindow { type_name, peer_id } => {
                assert_eq!(type_name, "Path Tap");
                assert_eq!(peer_id.as_deref(), Some("PEER1"));
            }
            other => panic!("expected SpawnWindow, got {:?}", other),
        }
    }

    #[test]
    fn continuation_path_parser() {
        assert_eq!(
            continuation_chain_id("/PEER1/system/continuation/CHAIN_X"),
            Some("CHAIN_X"),
        );
        assert_eq!(continuation_chain_id("/PEER1/app/notes/1"), None);
    }

    // -----------------------------------------------------------------
    // inspect entity / dump / find
    // -----------------------------------------------------------------

    fn ent_with_hash(t: &str, body: &[u8], hash: &str) -> EntityRead {
        EntityRead {
            entity_type: t.to_string(),
            data: body.to_vec(),
            content_hash: hash.to_string(),
        }
    }

    fn dump_fixture() -> StubBinding {
        StubBinding {
            bound: "PEER1".into(),
            bindings: vec![
                TreeListingEntry { path: "/PEER1/app/notes/one".into() },
                TreeListingEntry { path: "/PEER1/app/notes/two".into() },
                TreeListingEntry { path: "/PEER1/system/peers/PEER2".into() },
            ],
            entities: vec![
                (
                    "/PEER1/app/notes/one".into(),
                    ent_with_hash("app/note", &cbor_text("hello"), "aaaa1111bbbb"),
                ),
                (
                    "/PEER1/app/notes/two".into(),
                    // Same hash as /one — exercises --paths multi-match.
                    ent_with_hash("app/note", &cbor_text("hello"), "aaaa1111bbbb"),
                ),
                (
                    "/PEER1/system/peers/PEER2".into(),
                    ent_with_hash("system/peer", &cbor_text("peer2"), "cccc2222"),
                ),
            ],
        }
    }

    #[test]
    fn inspect_entity_at_existing_path_renders_full_dump() {
        let binding = dump_fixture();
        let output = entity_op(&binding, "PEER1", "/PEER1/app/notes/one");
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert_eq!(sections.len(), 1);
        let section = &sections[0];
        assert!(section.header.as_ref().unwrap().contains("entity /PEER1/app/notes/one"));
        assert!(section.entries.iter().any(|r| r == "path:  /PEER1/app/notes/one"));
        assert!(section.entries.iter().any(|r| r == "type:  app/note"));
        assert!(section.entries.iter().any(|r| r == "hash:  aaaa1111bbbb"));
        assert!(section.entries.iter().any(|r| r.starts_with("len:")));
        assert!(section.entries.iter().any(|r| r.contains("\"hello\"")));
    }

    #[test]
    fn inspect_entity_missing_path_shows_not_found_marker() {
        let binding = dump_fixture();
        let output = entity_op(&binding, "PEER1", "/PEER1/app/nothing");
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert!(sections[0].entries[0].contains("no entity at /PEER1/app/nothing"));
    }

    #[test]
    fn inspect_entity_renders_unknown_hash_marker_when_binding_omits_it() {
        let mut binding = dump_fixture();
        binding.entities[0].1.content_hash.clear();
        let output = entity_op(&binding, "PEER1", "/PEER1/app/notes/one");
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert!(sections[0].entries.iter().any(|r| r == "hash:  (unknown)"));
    }

    #[test]
    fn inspect_dump_by_hash_renders_dump_shape_without_paths_section_by_default() {
        let binding = dump_fixture();
        let output = dump_op(&binding, "PEER1", "aaaa1111bbbb", /*with_paths=*/ false);
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert_eq!(sections.len(), 1, "no --paths → one section");
        assert!(sections[0].header.as_ref().unwrap().contains("dump aaaa1111bbbb"));
        assert!(sections[0].entries.iter().any(|r| r == "hash:  aaaa1111bbbb"));
    }

    #[test]
    fn inspect_dump_with_paths_flag_enumerates_referring_paths() {
        let binding = dump_fixture();
        let output = dump_op(&binding, "PEER1", "aaaa1111bbbb", /*with_paths=*/ true);
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert_eq!(sections.len(), 2, "with --paths → entity-dump + paths section");
        let paths = &sections[1];
        assert!(paths.header.as_ref().unwrap().contains("paths referencing this hash"));
        assert!(paths.entries.iter().any(|p| p == "/PEER1/app/notes/one"));
        assert!(paths.entries.iter().any(|p| p == "/PEER1/app/notes/two"));
        assert!(!paths.entries.iter().any(|p| p == "/PEER1/system/peers/PEER2"));
    }

    #[test]
    fn inspect_dump_unknown_hash_shows_not_found_marker() {
        let binding = dump_fixture();
        let output = dump_op(&binding, "PEER1", "deadbeef", false);
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert!(sections[0].entries[0].contains("no entity with hash deadbeef"));
    }

    #[test]
    fn inspect_dump_parser_rejects_non_hex_hash() {
        let binding = dump_fixture();
        let shell = Shell::with_wd("PEER1", "/PEER1/");
        let err = dump(&shell, &["zzz"], &binding).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
        assert!(err.message.contains("hex"));
    }

    #[test]
    fn inspect_find_returns_matches_under_default_limit() {
        let binding = dump_fixture();
        let output = find_op(&binding, "PEER1", "notes", 200);
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert_eq!(sections[0].entries.len(), 2);
        assert!(sections[0].header.as_ref().unwrap().contains("2 matches"));
    }

    #[test]
    fn inspect_find_truncates_at_limit_with_more_marker() {
        let mut binding = dump_fixture();
        // Add 5 more matching paths so we exceed limit=3.
        for i in 0..5 {
            binding.bindings.push(TreeListingEntry {
                path: format!("/PEER1/app/notes/extra-{i}"),
            });
        }
        let output = find_op(&binding, "PEER1", "notes", 3);
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        // 3 path rows + 1 "… N more" marker row.
        assert_eq!(sections[0].entries.len(), 4);
        assert!(sections[0]
            .entries
            .last()
            .unwrap()
            .contains("more (raise with --limit"));
        assert!(sections[0].header.as_ref().unwrap().contains("of 7 matches"));
    }

    #[test]
    fn inspect_find_no_matches_shows_marker() {
        let binding = dump_fixture();
        let output = find_op(&binding, "PEER1", "nonexistent", 200);
        let VerbOutput::Listing { sections } = output else {
            panic!("expected Listing");
        };
        assert!(sections[0].entries[0].contains("no matches"));
    }

    #[test]
    fn inspect_find_parser_rejects_empty_substring() {
        let binding = dump_fixture();
        let shell = Shell::with_wd("PEER1", "/PEER1/");
        let err = find(&shell, &[""], &binding).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn inspect_find_parser_accepts_limit_flag() {
        let binding = dump_fixture();
        let shell = Shell::with_wd("PEER1", "/PEER1/");
        let out = find(&shell, &["notes", "--limit", "1"], &binding).unwrap();
        let VerbOutput::Listing { sections } = out else {
            panic!("expected Listing");
        };
        assert_eq!(sections[0].entries.len(), 2); // 1 row + "… N more" marker
    }

    #[test]
    fn inspect_find_parser_rejects_zero_limit() {
        let binding = dump_fixture();
        let shell = Shell::with_wd("PEER1", "/PEER1/");
        let err = find(&shell, &["x", "--limit", "0"], &binding).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn marker_path_parsers() {
        assert_eq!(
            marker_chain_id("/PEER1/system/runtime/chain-errors/lost/CX/0/r/0xabc"),
            Some("CX"),
        );
        let (k, r) = marker_kind_reason(
            "/PEER1/system/runtime/chain-errors/rejected/CX/1/cap_denied/0xdef",
        );
        assert_eq!(k, "rejected");
        assert_eq!(r, "cap_denied");
    }
}
