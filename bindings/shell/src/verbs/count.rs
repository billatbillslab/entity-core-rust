//! `count [<type>]` — count entities matching `<type>` (or total).
//!
//! Async streaming Lines:
//! - `Dispatched("→ count [type=<t>]")`
//! - `Complete("← <n>")` on success
//! - `Failed(ShellError)` on dispatch failure
//!
//! Empty filter is allowed (returns the unbounded total).
//!
//! Factored per guide §8.1 four-layer model: `count_op` is the typed
//! verb-op (no `Shell`; streaming output via `VerbOutput::Lines`
//! directly); `count` is the verb-parser (arg-validation only — no
//! path arg means no dispatcher-tier alias expansion).

use tokio::sync::mpsc;

use crate::binding::PeerBinding;
use crate::result::{ShellError, StreamChunk, VerbOutput};
use crate::runtime::BoxFuture;

/// Verb-op (§8.1). Issue a count for entities of `type_filter` (empty
/// string = no filter), streaming the result as a Dispatched chunk
/// followed by Complete or Failed.
pub fn count_op<S>(
    binding: &dyn PeerBinding,
    type_filter: &str,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<StreamChunk>(4);
    let dispatched = if type_filter.is_empty() {
        "→ count (no filter)".to_string()
    } else {
        format!("→ count type={}", type_filter)
    };
    let _ = tx.try_send(StreamChunk::Dispatched(dispatched));

    let fut = binding.count(binding.peer_id(), type_filter);
    let task = Box::pin(async move {
        let chunk = match fut.await {
            Ok(n) => StreamChunk::Complete(format!("← {}", n)),
            Err(e) => StreamChunk::Failed(ShellError::dispatch(format!("✗ count → {}", e))),
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Lines(rx)
}

/// Verb-parser (§8.1). Calls `count_op` with the optional type filter.
pub fn count<S>(
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let type_filter = args.first().copied().unwrap_or("");
    Ok(count_op(binding, type_filter, spawn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};

    struct StubBinding {
        result: Result<usize, String>,
    }

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
        fn count(
            &self,
            _pid: &str,
            _type_filter: &str,
        ) -> BoxFuture<'static, Result<usize, String>> {
            let r = self.result.clone();
            Box::pin(async move { r })
        }
    }

    fn drive(fut: BoxFuture<'static, ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut);
    }

    fn drive_recv(rx: &mut mpsc::Receiver<StreamChunk>) -> Option<StreamChunk> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(rx.recv())
    }

    #[test]
    fn empty_filter_emits_no_filter_dispatched() {
        let b = StubBinding { result: Ok(42) };
        let result = count(&[], &b, drive).unwrap();
        let mut rx = match result {
            VerbOutput::Lines(rx) => rx,
            _ => panic!(),
        };
        let dispatched = rx.try_recv().unwrap();
        assert!(matches!(dispatched, StreamChunk::Dispatched(ref s) if s.contains("no filter")));
    }

    #[test]
    fn type_filter_dispatched_and_complete() {
        let b = StubBinding { result: Ok(7) };
        let result = count(&["app/x"], &b, drive).unwrap();
        let mut rx = match result {
            VerbOutput::Lines(rx) => rx,
            _ => panic!(),
        };
        let dispatched = rx.try_recv().unwrap();
        assert!(matches!(dispatched, StreamChunk::Dispatched(ref s) if s.contains("type=app/x")));
        let complete = drive_recv(&mut rx).unwrap();
        assert!(matches!(complete, StreamChunk::Complete(ref s) if s.contains("← 7")));
    }
}
