//! `exec <handler_uri> <operation> [json-params]` — dispatch a handler op.
//!
//! Second async streaming verb (after `connect`). Returns
//! `VerbOutput::Dispatch(rx)` — `DispatchChunk` variants distinguish
//! handler-defined results from the textual stream chunks `Lines`
//! uses (per `GUIDE-SHELL-FRAMING.md` §3.3).
//!
//! JSON parameter parsing is the embedding's concern — see
//! `PeerBinding::execute` for the contract.
//!
//! Factored per guide §8.1 four-layer model: `exec_op` is the typed
//! verb-op (takes binding + peer_id + handler_uri + operation +
//! params_text + spawn directly, no `Shell`); `exec` is the verb-
//! parser. The handler-uri arg can carry an `@alias` prefix in the
//! `@alias/handler` form — that expansion happens at the dispatcher
//! tier (`dispatch_with_path_arg`).

use tokio::sync::mpsc;

use crate::binding::PeerBinding;
use crate::result::{DispatchChunk, ShellError, VerbOutput};
use crate::runtime::BoxFuture;
use crate::shell::Shell;

/// Verb-op (§8.1). Dispatch an exec to `handler_uri`'s `operation`,
/// streaming progress as `DispatchChunk`s. Reusable from non-shell
/// consumers driving handler calls without going through the verb-
/// parser (e.g., the execute-console panel).
pub fn exec_op<S>(
    binding: &dyn PeerBinding,
    peer_id: &str,
    handler_uri: String,
    operation: String,
    params_text: Option<String>,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<DispatchChunk>(4);
    let _ = tx.try_send(DispatchChunk::Dispatched(format!(
        "→ exec {} {}",
        handler_uri, operation
    )));

    let handler_uri_clone = handler_uri.clone();
    let operation_clone = operation.clone();
    let fut = binding.execute(peer_id, handler_uri, operation, params_text);
    let task = Box::pin(async move {
        let chunk = match fut.await {
            Ok(summary) => DispatchChunk::Complete(format!(
                "← exec {} {} → {}",
                handler_uri_clone, operation_clone, summary
            )),
            Err(e) => DispatchChunk::Failed(ShellError::dispatch(format!(
                "✗ exec {} {} → {}",
                handler_uri_clone, operation_clone, e
            ))),
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Dispatch(rx)
}

/// Verb-parser (§8.1). Parses arg-string-form into typed inputs and
/// calls `exec_op`. The handler-uri (arg[0]) is already alias-expanded
/// by the dispatcher.
pub fn exec<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    if args.len() < 2 {
        return Err(ShellError::usage(
            "exec: usage: exec <handler_uri> <operation> [json-params]",
        ));
    }
    let handler_uri = args[0].to_string();
    let operation = args[1].to_string();
    let params_text = if args.len() > 2 {
        let joined = args[2..].join(" ");
        if joined.trim().is_empty() {
            None
        } else {
            Some(joined)
        }
    } else {
        None
    };
    Ok(exec_op(
        binding,
        shell.peer_id(),
        handler_uri,
        operation,
        params_text,
        spawn,
    ))
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
        fn execute(
            &self,
            _peer_id: &str,
            _handler_uri: String,
            _operation: String,
            _params_text: Option<String>,
        ) -> BoxFuture<'static, Result<String, String>> {
            let r = self.result.clone();
            Box::pin(async move { r })
        }
    }

    fn drive(fut: BoxFuture<'static, ()>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(fut);
    }

    fn drive_recv(rx: &mut mpsc::Receiver<DispatchChunk>) -> Option<DispatchChunk> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(rx.recv())
    }

    #[test]
    fn too_few_args_returns_usage() {
        let b = StubBinding { bound: "alice".into(), result: Ok("ok".into()) };
        let shell = Shell::with_wd("alice", "/alice/");
        let err = exec(&shell, &["only-handler"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn success_path_streams_dispatched_then_complete() {
        let b = StubBinding { bound: "alice".into(), result: Ok("4 entities".into()) };
        let shell = Shell::with_wd("alice", "/alice/");
        let result = exec(&shell, &["system/tree", "list"], &b, drive).unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let dispatched = rx.try_recv().unwrap();
                assert!(matches!(dispatched, DispatchChunk::Dispatched(ref s) if s.contains("→ exec")));
                let complete = drive_recv(&mut rx).unwrap();
                assert!(matches!(complete, DispatchChunk::Complete(ref s) if s.contains("4 entities")));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn failure_path_emits_dispatch_failed() {
        let b = StubBinding { bound: "alice".into(), result: Err("handler not registered".into()) };
        let shell = Shell::with_wd("alice", "/alice/");
        let result = exec(&shell, &["system/tree", "list"], &b, drive).unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let _ = rx.try_recv().unwrap();
                let chunk = drive_recv(&mut rx).unwrap();
                match chunk {
                    DispatchChunk::Failed(err) => {
                        assert_eq!(err.code, crate::result::ErrorCode::Dispatch);
                        assert!(err.message.contains("handler not registered"));
                    }
                    other => panic!("expected Failed, got {:?}", other),
                }
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }
}
