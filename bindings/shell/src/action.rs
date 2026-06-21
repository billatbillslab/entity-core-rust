//! `AppActionSink` — embedding-side lifecycle hook.
//!
//! Verbs that need lifecycle operations the crate can't perform itself
//! (spawning windows, creating/deleting peers, installing tail
//! subscriptions) submit a `ShellRequest` through an `AppActionSink`.
//! The embedding maps the request to its own action enum / dispatch.
//!
//! This sink is
//! correctly egui-only — Godot's GDExtension embedding doesn't have
//! analogous lifecycle today. The default sink is a no-op so
//! embeddings without lifecycle ops aren't forced to implement
//! anything; verbs needing the sink degrade gracefully (the verb
//! itself decides the user-facing message).

/// Host + persistence config for a peer-create request. Mirrors
/// egui's `crate::peer_mode::PeerMode`; embeddings without a
/// peer-creation surface can ignore the variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMode {
    Frontend,
    BackendMemory,
    BackendOpfs,
}

impl PeerMode {
    pub fn label(self) -> &'static str {
        match self {
            PeerMode::Frontend => "frontend",
            PeerMode::BackendMemory => "backend (memory)",
            PeerMode::BackendOpfs => "backend (opfs)",
        }
    }
}

/// Lifecycle request submitted by a verb to the embedding. Variants
/// are enumerated for type safety; embedders match on the variant and
/// dispatch to their own action handlers.
#[derive(Debug, Clone)]
pub enum ShellRequest {
    /// Spawn a window of type `type_name` bound to `peer_id` (or the
    /// shell's bound peer when `None`).
    SpawnWindow {
        type_name: String,
        peer_id: Option<String>,
    },

    /// Create a new peer with the given mode and optional label.
    CreatePeer {
        mode: PeerMode,
        label: Option<String>,
    },

    /// Delete the peer with this id.
    DeletePeer { peer_id: String },

    /// Rename peer with this id to `label` (`None` clears the label).
    RenamePeer {
        peer_id: String,
        label: Option<String>,
    },

    /// Install a tail subscription against `prefix`. The embedding
    /// manages the subscription handle and streams change events
    /// into the shell's scrollback (or wherever it routes them).
    InstallTail { prefix: String },

    /// Stop any active tail subscription matching `target` (a path
    /// prefix or `"all"`).
    UninstallTail { target: String },
}

/// Embedding-supplied lifecycle dispatcher. Default impl is a no-op;
/// verbs that submit requests rely on the embedding overriding.
pub trait AppActionSink {
    fn submit(&self, request: ShellRequest);

    /// List currently-installed tail subscriptions. Used by `tails`.
    /// Default empty list (embeddings without tail support show
    /// "(no active tails)").
    fn list_tails(&self) -> Vec<TailInfo> {
        Vec::new()
    }

    /// Available window-type names for `open`. Per guide §4.3,
    /// `open` is Tier A — application-derived — so the catalog
    /// lives with the embedding. Default empty (verb reports the
    /// embedding doesn't expose any window types).
    fn available_windows(&self) -> Vec<String> {
        Vec::new()
    }

    /// Resolve a user-supplied window name to one of the embedding's
    /// canonical entries (tolerant of case, hyphens, spaces).
    /// Default: case-insensitive exact match against the list from
    /// `available_windows`. Embeddings with custom matching rules
    /// override.
    fn resolve_window_name(&self, input: &str) -> Option<String> {
        let key = normalize_window_token(input);
        self.available_windows()
            .into_iter()
            .find(|name| normalize_window_token(name) == key)
    }
}

fn normalize_window_token(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// No-op sink. Used as a sentinel for embeddings that don't supply
/// one (the verb degrades — e.g., `peer create` returns a message
/// indicating no lifecycle is wired). Default `impl AppActionSink`
/// for `()` so consumers can pass `&()` when they want the no-op.
impl AppActionSink for () {
    fn submit(&self, _request: ShellRequest) {}
}

/// Tail subscription state — read by `tails`, manipulated by
/// `untail`. Owned by the embedding (subscription handles are
/// host-specific); the crate's `tails` verb reads via this view.
#[derive(Debug, Clone)]
pub struct TailInfo {
    pub prefix: String,
    pub active: bool,
}
