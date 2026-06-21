//! `query <type>` — find entities of `<type>` in the bound peer's tree.
//!
//! Async streaming Lines:
//! - `Dispatched("→ query type=<t> limit=50")`
//! - one `Line(path entity_type)` chunk per match
//! - `Complete("← N match(es), total=T, has_more=B")`
//! - or `Failed(ShellError)` on dispatch failure
//!
//! Default limit 50 — matches the egui shell ethos of "type filter or
//! nothing useful." Empty `args` → Usage err.
//!
//! Factored per guide §8.1 four-layer model: `query_op` is the typed
//! verb-op (no `Shell`; takes binding + type-filter + limit + spawn,
//! returns the stream-typed `VerbOutput::Lines(rx)` directly); `query`
//! is the verb-parser (arg-validation only — no path arg means no
//! dispatcher-tier alias expansion is required). Validates the §8.1
//! "verb-op outputs MAY be stream-typed" sub-pin: in this impl the
//! op produces `VerbOutput::Lines` directly; the parser does no
//! result-variant projection (the projection is identity because
//! `mpsc::Receiver` IS the streaming primitive of `Result::lines`).

use tokio::sync::mpsc;

use crate::binding::PeerBinding;
use crate::result::{ShellError, StreamChunk, VerbOutput};
use crate::runtime::BoxFuture;

const DEFAULT_LIMIT: usize = 50;

/// Verb-op (§8.1). Issue a query for entities of `type_filter`,
/// streaming results as `StreamChunk`s through a `mpsc::Receiver`.
/// Reusable from non-shell consumers (a query-results panel rendering
/// streaming matches without going through the verb-parser).
pub fn query_op<S>(
    binding: &dyn PeerBinding,
    type_filter: &str,
    limit: usize,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<StreamChunk>(64);
    let _ = tx.try_send(StreamChunk::Dispatched(format!(
        "→ query type={} limit={}",
        type_filter, limit
    )));

    let fut = binding.query(binding.peer_id(), type_filter, limit);
    let task = Box::pin(async move {
        match fut.await {
            Ok(results) => {
                for m in &results.matches {
                    let _ = tx
                        .send(StreamChunk::Line(format!("  {}  {}", m.path, m.entity_type)))
                        .await;
                }
                let _ = tx
                    .send(StreamChunk::Complete(format!(
                        "← {} match(es), total={}, has_more={}",
                        results.matches.len(),
                        results.total,
                        results.has_more
                    )))
                    .await;
            }
            Err(e) => {
                let _ = tx
                    .send(StreamChunk::Failed(ShellError::dispatch(format!(
                        "✗ query → {}",
                        e
                    ))))
                    .await;
            }
        }
    });
    spawn(task);
    VerbOutput::Lines(rx)
}

/// Verb-parser (§8.1). Validates the type-filter arg, calls `query_op`.
/// `Shell` is not needed — `query` has no path arg (the type filter is
/// not a path) and the verb-op uses `binding.peer_id()` directly.
pub fn query<S>(
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let type_filter = args
        .first()
        .copied()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            ShellError::usage("query: usage: query <type>  (e.g. `query app/state/setting`)")
        })?;
    Ok(query_op(binding, type_filter, DEFAULT_LIMIT, spawn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, QueryMatch, QueryResults, TreeListingEntry};

    struct StubBinding {
        result: Result<QueryResults, String>,
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
        fn query(
            &self,
            _pid: &str,
            _type_filter: &str,
            _limit: usize,
        ) -> BoxFuture<'static, Result<QueryResults, String>> {
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
    fn empty_filter_returns_usage() {
        let b = StubBinding {
            result: Ok(QueryResults { matches: Vec::new(), total: 0, has_more: false }),
        };
        let err = query(&[], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn streams_dispatched_lines_and_complete() {
        let b = StubBinding {
            result: Ok(QueryResults {
                matches: vec![
                    QueryMatch { path: "/alice/a".into(), entity_type: "app/x".into() },
                    QueryMatch { path: "/alice/b".into(), entity_type: "app/x".into() },
                ],
                total: 2,
                has_more: false,
            }),
        };
        let result = query(&["app/x"], &b, drive).unwrap();
        let mut rx = match result {
            VerbOutput::Lines(rx) => rx,
            other => panic!("unexpected variant: {:?}", other),
        };
        let dispatched = rx.try_recv().unwrap();
        assert!(matches!(dispatched, StreamChunk::Dispatched(_)));
        let line1 = drive_recv(&mut rx).unwrap();
        assert!(matches!(line1, StreamChunk::Line(ref s) if s.contains("/alice/a")));
        let line2 = drive_recv(&mut rx).unwrap();
        assert!(matches!(line2, StreamChunk::Line(ref s) if s.contains("/alice/b")));
        let complete = drive_recv(&mut rx).unwrap();
        assert!(matches!(complete, StreamChunk::Complete(ref s) if s.contains("2 match(es)")));
    }

    #[test]
    fn failure_emits_failed_chunk() {
        let b = StubBinding { result: Err("backend down".into()) };
        let result = query(&["x"], &b, drive).unwrap();
        let mut rx = match result {
            VerbOutput::Lines(rx) => rx,
            _ => panic!(),
        };
        let _ = rx.try_recv().unwrap();
        let chunk = drive_recv(&mut rx).unwrap();
        match chunk {
            StreamChunk::Failed(err) => {
                assert_eq!(err.code, crate::result::ErrorCode::Dispatch);
                assert!(err.message.contains("backend down"));
            }
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn query_op_streams_directly() {
        let b = StubBinding {
            result: Ok(QueryResults {
                matches: vec![QueryMatch { path: "/alice/x".into(), entity_type: "t".into() }],
                total: 1,
                has_more: false,
            }),
        };
        let output = query_op(&b, "t", 10, drive);
        let mut rx = match output {
            VerbOutput::Lines(rx) => rx,
            _ => panic!(),
        };
        let _dispatched = rx.try_recv().unwrap();
        let line = drive_recv(&mut rx).unwrap();
        assert!(matches!(line, StreamChunk::Line(ref s) if s.contains("/alice/x")));
    }
}
