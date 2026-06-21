//! `Shell` — session state for one shell instance.
//!
//! Phase 3a scope: minimal — bound peer id + current working directory.
//! Subsequent phases lift history, alias resolution, and the dispatcher
//! handle as the rest of Tier C migrates in.
//!
//! Per `GUIDE-SHELL-FRAMING.md` §3.5, `Shell::new` is the consumer-facing
//! construction-time hook. Trait parameters (`PeerBinding`, optional
//! `SelectionSink`, persistence root) are added as later verbs require
//! them — pwd, the pattern-setter, needs none of them.

/// A shell session. One per palette / window / REPL instance.
///
/// Holds session state the embedding doesn't need to own directly. The
/// embedding constructs a `Shell` per peer-bound window, calls verbs
/// against it, and renders the returned `VerbOutput` via its
/// modality-specific adapter.
pub struct Shell {
    /// The peer this shell is bound to. Tree ops scope to this peer
    /// regardless of the first path segment.
    peer_id: String,
    /// Current working directory. Starts at `/{peer_id}/`.
    wd: String,
}

impl Shell {
    /// Construct a new shell bound to `peer_id`. `wd` is initialized to
    /// the peer's tree root.
    pub fn new(peer_id: impl Into<String>) -> Self {
        let peer_id = peer_id.into();
        let wd = format!("/{}/", peer_id);
        Self { peer_id, wd }
    }

    /// Construct a shell with an explicit initial wd. Used by the
    /// embedding when restoring persisted state.
    pub fn with_wd(peer_id: impl Into<String>, wd: impl Into<String>) -> Self {
        Self { peer_id: peer_id.into(), wd: wd.into() }
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn wd(&self) -> &str {
        &self.wd
    }

    /// Mutate the working directory. Path validation / publication is
    /// the calling verb's responsibility (e.g., `cd` resolves +
    /// validates before calling).
    pub fn set_wd(&mut self, wd: impl Into<String>) {
        self.wd = wd.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_initializes_wd_to_peer_root() {
        let shell = Shell::new("alice");
        assert_eq!(shell.peer_id(), "alice");
        assert_eq!(shell.wd(), "/alice/");
    }

    #[test]
    fn with_wd_uses_supplied_path() {
        let shell = Shell::with_wd("bob", "/bob/app/");
        assert_eq!(shell.wd(), "/bob/app/");
    }

    #[test]
    fn set_wd_updates_in_place() {
        let mut shell = Shell::new("carol");
        shell.set_wd("/carol/system/");
        assert_eq!(shell.wd(), "/carol/system/");
    }
}
