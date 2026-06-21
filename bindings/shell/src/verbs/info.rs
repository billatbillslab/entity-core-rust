//! `info` — bound/primary peer, arm, counts, wd.
//!
//! Pure read against `PeerBinding`. Renamed from `status` in egui's
//! Phase 2 per `GUIDE-SHELL-FRAMING.md` §4.5 (cross-impl 9-core
//! convergence).
//!
//! Factored per guide §8.1 four-layer model: `info_op` is the typed
//! verb-op (takes the wd as a string, no `Shell` handle); `info` is
//! the verb-parser. `info` has no path args today, so the dispatcher
//! does no alias expansion for it.

use crate::binding::PeerBinding;
use crate::display;
use crate::result::{InfoRow, ShellError, VerbOutput};
use crate::shell::Shell;

/// Verb-op (§8.1). Assemble the info rows given a wd string and the
/// peer-binding. Reusable from non-shell consumers (e.g., an admin
/// panel rendering peer status) by passing any wd-like string or `""`.
pub fn info_op(
    binding: &dyn PeerBinding,
    wd: &str,
) -> Result<VerbOutput, ShellError> {
    let bound = binding.peer_id().to_string();
    let primary = binding.primary_peer_id();
    let local_count = binding.peer_ids().len();
    let connected_count = binding.connected_peers().len();
    let arm = binding.primary_arm();

    Ok(VerbOutput::Info(vec![
        InfoRow::labeled(
            "bound peer",
            format!("{} ({})", bound, display::short_pid(&bound)),
        ),
        InfoRow::labeled(
            "primary peer",
            format!("{} ({})", primary, display::short_pid(&primary)),
        ),
        InfoRow::labeled("primary arm", arm),
        InfoRow::labeled("local peers", local_count.to_string()),
        InfoRow::labeled("connections", connected_count.to_string()),
        InfoRow::labeled("wd", wd.to_string()),
    ]))
}

/// Verb-parser (§8.1). Calls `info_op` with the shell's wd.
pub fn info(
    shell: &Shell,
    _args: &[&str],
    binding: &dyn PeerBinding,
) -> Result<VerbOutput, ShellError> {
    info_op(binding, shell.wd())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};

    struct StubBinding {
        bound: String,
        primary: String,
        peers: Vec<String>,
        remotes: Vec<String>,
        arm: &'static str,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.bound }
        fn primary_peer_id(&self) -> String { self.primary.clone() }
        fn peer_ids(&self) -> Vec<String> { self.peers.clone() }
        fn connected_peers(&self) -> Vec<String> { self.remotes.clone() }
        fn peer_label(&self, _pid: &str) -> Option<String> { None }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }
        fn primary_arm(&self) -> &'static str { self.arm }
    }

    #[test]
    fn returns_six_labeled_rows() {
        let b = StubBinding {
            bound: "alice_long_pid_12345".into(),
            primary: "alice_long_pid_12345".into(),
            peers: vec!["alice_long_pid_12345".into(), "bob".into()],
            remotes: vec!["remote1".into()],
            arm: "Direct",
        };
        let shell = Shell::with_wd("alice_long_pid_12345", "/alice_long_pid_12345/system/");
        match info(&shell, &[], &b).unwrap() {
            VerbOutput::Info(rows) => {
                assert_eq!(rows.len(), 6);
                assert_eq!(rows[0].label.as_deref(), Some("bound peer"));
                assert!(rows[0].value.contains("alice_lo"));
                assert_eq!(rows[2].label.as_deref(), Some("primary arm"));
                assert_eq!(rows[2].value, "Direct");
                assert_eq!(rows[3].value, "2");
                assert_eq!(rows[4].value, "1");
                assert_eq!(rows[5].label.as_deref(), Some("wd"));
                assert_eq!(rows[5].value, "/alice_long_pid_12345/system/");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn default_arm_is_local() {
        struct Minimal;
        impl PeerBinding for Minimal {
            fn peer_id(&self) -> &str { "x" }
            fn primary_peer_id(&self) -> String { "x".into() }
            fn peer_ids(&self) -> Vec<String> { vec!["x".into()] }
            fn connected_peers(&self) -> Vec<String> { Vec::new() }
            fn peer_label(&self, _pid: &str) -> Option<String> { None }
            fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<TreeListingEntry> {
                Vec::new()
            }
            fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }
        }
        let shell = Shell::with_wd("x", "/x/");
        match info(&shell, &[], &Minimal).unwrap() {
            VerbOutput::Info(rows) => {
                assert_eq!(rows[2].value, "local");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }
}
