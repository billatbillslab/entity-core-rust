//! `connect <address>` — open a connection from the bound peer.
//!
//! First async streaming verb. Returns `VerbOutput::Lines(rx)`:
//! - `Dispatched("→ connecting to <addr>")` — synchronous, pre-queued
//!   so consumers see immediate feedback.
//! - `Complete("← connected to <short> (<addr>)")` on success.
//! - `Failed(ShellError)` on failure.
//!
//! Channel close signals verb done.
//!
//! Dispatch is from the **bound peer**. Each shell is peer-scoped —
//! connecting from a backend-bound shell originates the connection on
//! that backend (which is what makes `xworker://<other-backend-pid>`
//! meaningful — only that backend has the MessagePortConnector wired).
//!
//! The crate doesn't own a runtime; the embedding passes a spawner
//! closure that drives the producer task on its own runtime
//! (tokio / wasm-bindgen-futures / etc.).
//!
//! Factored per guide §8.1 four-layer model: `connect_op` is the
//! typed verb-op (takes binding + from_peer + address + spawn directly,
//! no `Shell`); `connect` is the verb-parser. The address arg is a
//! literal network address (`ws://...`, `memory://...`,
//! `xworker://...`) — no alias resolution applies.

use tokio::sync::mpsc;

use crate::binding::PeerBinding;
use crate::display;
use crate::result::{ShellError, StreamChunk, VerbOutput};
use crate::runtime::BoxFuture;
use crate::shell::Shell;

/// Verb-op (§8.1). Dispatch a connect from `from_peer` to `address`,
/// streaming progress as `StreamChunk`s. Reusable from non-shell
/// consumers (e.g., a connection-admin panel adding a remote).
pub fn connect_op<S>(
    binding: &dyn PeerBinding,
    from_peer: &str,
    address: String,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<StreamChunk>(4);
    let _ = tx.try_send(StreamChunk::Dispatched(format!("→ connecting to {}", address)));

    let address_clone = address.clone();
    let connect_fut = binding.connect_peer(from_peer, address);
    let task = Box::pin(async move {
        let chunk = match connect_fut.await {
            Ok(remote_pid) => StreamChunk::Complete(format!(
                "← connected to {} ({})",
                display::short_pid(&remote_pid),
                address_clone
            )),
            Err(e) => StreamChunk::Failed(ShellError::transport(format!(
                "✗ connect {} → {}",
                address_clone, e
            ))),
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Lines(rx)
}

/// Verb-parser (§8.1). Validates the address arg, pulls `from_peer`
/// from the shell, calls `connect_op`.
pub fn connect<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let addr = args
        .first()
        .ok_or_else(|| {
            ShellError::usage("connect: usage: connect <ws://addr | memory://peer-id>")
        })?
        .to_string();
    Ok(connect_op(binding, shell.peer_id(), addr, spawn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};

    struct StubBinding {
        bound: String,
        result: Result<String, String>,
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { &self.bound }
        fn primary_peer_id(&self) -> String { self.bound.clone() }
        fn peer_ids(&self) -> Vec<String> { vec![self.bound.clone()] }
        fn connected_peers(&self) -> Vec<String> { Vec::new() }
        fn peer_label(&self, _pid: &str) -> Option<String> { None }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }
        fn connect_peer(
            &self,
            _from_peer: &str,
            _address: String,
        ) -> BoxFuture<'static, Result<String, String>> {
            let r = self.result.clone();
            Box::pin(async move { r })
        }
    }

    #[test]
    fn missing_address_returns_usage() {
        let b = StubBinding { bound: "alice".into(), result: Ok("x".into()) };
        let shell = Shell::with_wd("alice", "/alice/");
        let err = connect(&shell, &[], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    fn drive(fut: BoxFuture<'static, ()>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(fut);
    }

    fn drive_recv(rx: &mut mpsc::Receiver<StreamChunk>) -> Option<StreamChunk> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(rx.recv())
    }

    #[test]
    fn success_path_drains_dispatched_then_complete() {
        let b = StubBinding { bound: "alice".into(), result: Ok("remote_long_pid_abcdef".into()) };
        let shell = Shell::with_wd("alice", "/alice/");
        let result = connect(&shell, &["ws://localhost:9999"], &b, drive).unwrap();
        match result {
            VerbOutput::Lines(mut rx) => {
                let dispatched = rx.try_recv().expect("dispatched chunk");
                assert!(matches!(dispatched, StreamChunk::Dispatched(ref s) if s.contains("→ connecting")));
                let complete = drive_recv(&mut rx).expect("complete chunk");
                assert!(matches!(complete, StreamChunk::Complete(ref s) if s.contains("← connected")));
                assert!(drive_recv(&mut rx).is_none());
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn failure_path_emits_failed_chunk() {
        let b = StubBinding { bound: "alice".into(), result: Err("refused".into()) };
        let shell = Shell::with_wd("alice", "/alice/");
        let result = connect(&shell, &["ws://nowhere"], &b, drive).unwrap();
        match result {
            VerbOutput::Lines(mut rx) => {
                let _dispatched = rx.try_recv().unwrap();
                let chunk = drive_recv(&mut rx).unwrap();
                match chunk {
                    StreamChunk::Failed(err) => {
                        assert_eq!(err.code, crate::result::ErrorCode::Transport);
                        assert!(err.message.contains("refused"));
                    }
                    other => panic!("expected Failed, got {:?}", other),
                }
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }
}
