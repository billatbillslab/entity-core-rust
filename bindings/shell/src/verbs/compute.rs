//! `compute <eval|install|uninstall|list|show>` — `system/compute`
//! extension verbs.
//!
//! Thin formatters over `PeerBinding::compute_*`. The embedding wraps
//! the SDK's `ComputeOps` (`bindings/sdk/src/compute.rs`) and renders
//! values into the binding's stringly-typed return shapes — see the
//! shell verb guide §8 for the output contract.
//!
//! Sub-op routing matches the `peer.rs` pattern: a single dispatcher
//! entry (`compute`) parses the first arg as the sub-op and delegates.
//! All five sub-ops are async (`eval`/`install`/`uninstall` dispatch
//! EXECUTE; `list` runs an L1 query and `show` an on-demand `Get` so they
//! work on the Worker arm, where there is no main-thread store): each
//! returns `VerbOutput::Dispatch(rx)` and relies on the consumer-supplied
//! `spawn` closure to drive the producer task. On the Direct arm the
//! futures resolve immediately.

use tokio::sync::mpsc;

use crate::binding::PeerBinding;
use crate::result::{DispatchChunk, ShellError, VerbOutput};
use crate::runtime::BoxFuture;
use crate::shell::Shell;

/// Verb-parser (§8.1). Top-level sub-op router; delegates to the
/// per-op verb-parser, which calls into the verb-op. Embeddings that
/// want one of the verb-ops directly (e.g. an authoring panel running
/// `eval` without going through arg parsing) can call `eval_op`,
/// `install_op`, etc., themselves.
pub fn compute<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (sub, rest) = args.split_first().ok_or_else(|| {
        ShellError::usage(
            "compute: usage: compute <eval|install|uninstall|list|show> [args...]",
        )
    })?;
    match *sub {
        "eval" => eval(shell, rest, binding, spawn),
        "install" => install(shell, rest, binding, spawn),
        "uninstall" => uninstall(shell, rest, binding, spawn),
        "list" => Ok(list_op(shell.peer_id(), binding, spawn)),
        "show" => show(shell, rest, binding, spawn),
        other => Err(ShellError::unknown(format!(
            "compute: unknown subcommand '{}'. Try: eval, install, uninstall, list, show.",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// compute eval <expr-path> [--budget N]
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Dispatch `system/compute:eval` against
/// `expression_path` and stream the result as a `DispatchChunk`.
/// Embedding-supplied `binding.compute_eval` returns a pre-rendered
/// multi-line string; the verb formats the dispatched/complete arrows.
pub fn eval_op<S>(
    binding: &dyn PeerBinding,
    peer_id: &str,
    expression_path: String,
    budget: Option<u64>,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<DispatchChunk>(2);
    let _ = tx.try_send(DispatchChunk::Dispatched(format!(
        "→ compute eval {}",
        expression_path
    )));

    let path_clone = expression_path.clone();
    let fut = binding.compute_eval(peer_id, expression_path, budget);
    let task = Box::pin(async move {
        let chunk = match fut.await {
            Ok(rendered) => DispatchChunk::Complete(rendered),
            Err(e) => DispatchChunk::Failed(ShellError::dispatch(format!(
                "✗ compute eval {} → {}",
                path_clone, e
            ))),
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Dispatch(rx)
}

fn eval<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let mut path: Option<String> = None;
    let mut budget: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--budget" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    ShellError::usage("compute eval: --budget needs a number")
                })?;
                budget = Some(v.parse::<u64>().map_err(|_| {
                    ShellError::usage(format!(
                        "compute eval: --budget value '{}' is not a non-negative integer",
                        v
                    ))
                })?);
                i += 2;
            }
            other if other.starts_with("--") => {
                return Err(ShellError::usage(format!(
                    "compute eval: unknown flag '{}'",
                    other
                )));
            }
            other => {
                if path.is_some() {
                    return Err(ShellError::usage(format!(
                        "compute eval: unexpected positional arg '{}'",
                        other
                    )));
                }
                path = Some(other.to_string());
                i += 1;
            }
        }
    }
    let path = path.ok_or_else(|| {
        ShellError::usage("compute eval: usage: compute eval <expr-path> [--budget N]")
    })?;
    Ok(eval_op(binding, shell.peer_id(), path, budget, spawn))
}

// ---------------------------------------------------------------------------
// compute install <root-path> [--result-path P]
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Dispatch `system/compute:install` against
/// `root_expression_path` and stream the result. The binding's
/// `compute_install` returns the chosen `(subgraph_path, result_path)`
/// pair; the verb formats labeled rows into a `Complete` chunk.
pub fn install_op<S>(
    binding: &dyn PeerBinding,
    peer_id: &str,
    root_expression_path: String,
    result_path: Option<String>,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<DispatchChunk>(2);
    let _ = tx.try_send(DispatchChunk::Dispatched(format!(
        "→ compute install {}",
        root_expression_path
    )));

    let root_clone = root_expression_path.clone();
    let fut = binding.compute_install(peer_id, root_expression_path, result_path);
    let task = Box::pin(async move {
        let chunk = match fut.await {
            Ok((subgraph, result)) => DispatchChunk::Complete(format!(
                "← compute install {}\n  subgraph: {}\n  result path: {}",
                root_clone, subgraph, result
            )),
            Err(e) => DispatchChunk::Failed(ShellError::dispatch(format!(
                "✗ compute install {} → {}",
                root_clone, e
            ))),
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Dispatch(rx)
}

fn install<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let mut path: Option<String> = None;
    let mut result_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--result-path" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    ShellError::usage("compute install: --result-path needs a path")
                })?;
                result_path = Some((*v).to_string());
                i += 2;
            }
            other if other.starts_with("--") => {
                return Err(ShellError::usage(format!(
                    "compute install: unknown flag '{}'",
                    other
                )));
            }
            other => {
                if path.is_some() {
                    return Err(ShellError::usage(format!(
                        "compute install: unexpected positional arg '{}'",
                        other
                    )));
                }
                path = Some(other.to_string());
                i += 1;
            }
        }
    }
    let path = path.ok_or_else(|| {
        ShellError::usage(
            "compute install: usage: compute install <root-path> [--result-path P]",
        )
    })?;
    Ok(install_op(binding, shell.peer_id(), path, result_path, spawn))
}

// ---------------------------------------------------------------------------
// compute uninstall <subgraph-path>
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Dispatch `system/compute:uninstall`.
pub fn uninstall_op<S>(
    binding: &dyn PeerBinding,
    peer_id: &str,
    subgraph_path: String,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<DispatchChunk>(2);
    let _ = tx.try_send(DispatchChunk::Dispatched(format!(
        "→ compute uninstall {}",
        subgraph_path
    )));

    let path_clone = subgraph_path.clone();
    let fut = binding.compute_uninstall(peer_id, subgraph_path);
    let task = Box::pin(async move {
        let chunk = match fut.await {
            Ok(()) => DispatchChunk::Complete(format!("uninstalled: {}", path_clone)),
            Err(e) => DispatchChunk::Failed(ShellError::dispatch(format!(
                "✗ compute uninstall {} → {}",
                path_clone, e
            ))),
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Dispatch(rx)
}

fn uninstall<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let path = args.first().ok_or_else(|| {
        ShellError::usage("compute uninstall: usage: compute uninstall <subgraph-path>")
    })?;
    Ok(uninstall_op(
        binding,
        shell.peer_id(),
        (*path).to_string(),
        spawn,
    ))
}

// ---------------------------------------------------------------------------
// compute list                       (async — L1 query on the Worker arm)
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Read installed subgraphs from `binding.compute_list`
/// (async — the Worker arm resolves it via an L1 query round-trip; Direct
/// resolves immediately) and stream the formatted listing as a
/// `DispatchChunk::Complete`. The header line carries the count; one
/// indented row per subgraph follows.
pub fn list_op<S>(peer_id: &str, binding: &dyn PeerBinding, spawn: S) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<DispatchChunk>(2);
    let fut = binding.compute_list(peer_id);
    let task = Box::pin(async move {
        let chunk = match fut.await {
            Ok(rows) => {
                let mut lines = vec![format!("installed subgraphs ({})", rows.len())];
                for (subgraph_path, root_expression_path, status) in rows {
                    lines.push(format!(
                        "  {}  ←  {}  ({})",
                        subgraph_path, root_expression_path, status
                    ));
                }
                DispatchChunk::Complete(lines.join("\n"))
            }
            Err(e) => {
                DispatchChunk::Failed(ShellError::dispatch(format!("✗ compute list → {}", e)))
            }
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Dispatch(rx)
}

// ---------------------------------------------------------------------------
// compute show <subgraph-path>       (async — on-demand Get on the Worker arm)
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Read subgraph metadata at `subgraph_path` (async — the
/// Worker arm resolves it via an on-demand `Get`; Direct resolves
/// immediately) and stream the labeled rows as a `DispatchChunk::Complete`.
/// `Ok(None)` from the binding → a `Failed`/usage chunk so the user sees a
/// clear "no subgraph here" message rather than empty output.
pub fn show_op<S>(
    binding: &dyn PeerBinding,
    peer_id: &str,
    subgraph_path: String,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<DispatchChunk>(2);
    let path_clone = subgraph_path.clone();
    let fut = binding.compute_show(peer_id, subgraph_path);
    let task = Box::pin(async move {
        let chunk = match fut.await {
            Ok(Some(rows)) => {
                let lines: Vec<String> = rows
                    .into_iter()
                    .map(|(label, value)| format!("  {}: {}", label, value))
                    .collect();
                DispatchChunk::Complete(lines.join("\n"))
            }
            Ok(None) => DispatchChunk::Failed(ShellError::usage(format!(
                "compute show: no subgraph bound at {}",
                path_clone
            ))),
            Err(e) => DispatchChunk::Failed(ShellError::dispatch(format!(
                "✗ compute show {} → {}",
                path_clone, e
            ))),
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Dispatch(rx)
}

fn show<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let path = args.first().ok_or_else(|| {
        ShellError::usage("compute show: usage: compute show <subgraph-path>")
    })?;
    Ok(show_op(binding, shell.peer_id(), path.to_string(), spawn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};
    use std::sync::Mutex;

    struct StubBinding {
        eval_result: Mutex<Option<Result<String, String>>>,
        install_result: Mutex<Option<Result<(String, String), String>>>,
        uninstall_result: Mutex<Option<Result<(), String>>>,
        list_result: Vec<(String, String, String)>,
        show_result: Option<Vec<(String, String)>>,
    }

    impl StubBinding {
        fn empty() -> Self {
            Self {
                eval_result: Mutex::new(None),
                install_result: Mutex::new(None),
                uninstall_result: Mutex::new(None),
                list_result: Vec::new(),
                show_result: None,
            }
        }
    }

    impl PeerBinding for StubBinding {
        fn peer_id(&self) -> &str { "p1" }
        fn primary_peer_id(&self) -> String { "p1".into() }
        fn peer_ids(&self) -> Vec<String> { vec!["p1".into()] }
        fn connected_peers(&self) -> Vec<String> { Vec::new() }
        fn peer_label(&self, _pid: &str) -> Option<String> { None }
        fn tree_listing(&self, _pid: &str, _prefix: &str) -> Vec<TreeListingEntry> {
            Vec::new()
        }
        fn get_entity(&self, _pid: &str, _path: &str) -> Option<EntityRead> { None }

        fn compute_eval(
            &self,
            _peer_id: &str,
            _expr_path: String,
            _budget: Option<u64>,
        ) -> BoxFuture<'static, Result<String, String>> {
            let r = self
                .eval_result
                .lock()
                .unwrap()
                .clone()
                .expect("test setup forgot to populate eval_result");
            Box::pin(async move { r })
        }

        fn compute_install(
            &self,
            _peer_id: &str,
            _root_expression_path: String,
            _result_path: Option<String>,
        ) -> BoxFuture<'static, Result<(String, String), String>> {
            let r = self
                .install_result
                .lock()
                .unwrap()
                .clone()
                .expect("test setup forgot to populate install_result");
            Box::pin(async move { r })
        }

        fn compute_uninstall(
            &self,
            _peer_id: &str,
            _subgraph_path: String,
        ) -> BoxFuture<'static, Result<(), String>> {
            let r = self
                .uninstall_result
                .lock()
                .unwrap()
                .clone()
                .expect("test setup forgot to populate uninstall_result");
            Box::pin(async move { r })
        }

        fn compute_list(
            &self,
            _peer_id: &str,
        ) -> BoxFuture<'static, Result<Vec<(String, String, String)>, String>> {
            let r = self.list_result.clone();
            Box::pin(async move { Ok(r) })
        }

        fn compute_show(
            &self,
            _peer_id: &str,
            _subgraph_path: String,
        ) -> BoxFuture<'static, Result<Option<Vec<(String, String)>>, String>> {
            let r = self.show_result.clone();
            Box::pin(async move { Ok(r) })
        }
    }

    fn shell() -> Shell {
        Shell::with_wd("p1", "/p1/")
    }

    fn drive(fut: BoxFuture<'static, ()>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(fut);
    }

    fn drive_recv<T>(rx: &mut mpsc::Receiver<T>) -> Option<T> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(rx.recv())
    }

    // ---------- eval ----------

    #[test]
    fn eval_missing_path_returns_usage() {
        let b = StubBinding::empty();
        let err = compute(&shell(), &["eval"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn eval_success_streams_dispatched_then_complete() {
        let b = StubBinding::empty();
        *b.eval_result.lock().unwrap() =
            Some(Ok("  value: Int(42)\n  entity type: compute/result".into()));
        let result =
            compute(&shell(), &["eval", "/p1/lit"], &b, drive).unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let d = rx.try_recv().unwrap();
                assert!(matches!(d, DispatchChunk::Dispatched(ref s) if s.contains("compute eval")));
                let c = drive_recv(&mut rx).unwrap();
                assert!(matches!(c, DispatchChunk::Complete(ref s) if s.contains("Int(42)")));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn eval_failure_emits_dispatch_failed() {
        let b = StubBinding::empty();
        *b.eval_result.lock().unwrap() = Some(Err("budget_exhausted".into()));
        let result =
            compute(&shell(), &["eval", "/p1/lit"], &b, drive).unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let _ = rx.try_recv().unwrap();
                let chunk = drive_recv(&mut rx).unwrap();
                match chunk {
                    DispatchChunk::Failed(err) => {
                        assert_eq!(err.code, crate::result::ErrorCode::Dispatch);
                        assert!(err.message.contains("budget_exhausted"));
                    }
                    other => panic!("expected Failed, got {:?}", other),
                }
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn eval_parses_budget_flag() {
        let b = StubBinding::empty();
        let err = compute(&shell(), &["eval", "/p1/lit", "--budget"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
        let err = compute(&shell(), &["eval", "/p1/lit", "--budget", "abc"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
        // Happy path: budget parses, dispatch proceeds.
        *b.eval_result.lock().unwrap() = Some(Ok("  value: Int(1)".into()));
        let result =
            compute(&shell(), &["eval", "/p1/lit", "--budget", "1000"], &b, drive).unwrap();
        assert!(matches!(result, VerbOutput::Dispatch(_)));
    }

    // ---------- install ----------

    #[test]
    fn install_missing_path_returns_usage() {
        let b = StubBinding::empty();
        let err = compute(&shell(), &["install"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn install_success_renders_subgraph_and_result_paths() {
        let b = StubBinding::empty();
        *b.install_result.lock().unwrap() = Some(Ok((
            "/p1/system/compute/processes/abc".into(),
            "/p1/app/x/result".into(),
        )));
        let result =
            compute(&shell(), &["install", "/p1/app/x"], &b, drive).unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let _ = rx.try_recv().unwrap();
                let c = drive_recv(&mut rx).unwrap();
                match c {
                    DispatchChunk::Complete(s) => {
                        assert!(s.contains("/p1/system/compute/processes/abc"));
                        assert!(s.contains("/p1/app/x/result"));
                    }
                    other => panic!("expected Complete, got {:?}", other),
                }
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    // ---------- uninstall ----------

    #[test]
    fn uninstall_missing_path_returns_usage() {
        let b = StubBinding::empty();
        let err = compute(&shell(), &["uninstall"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn uninstall_success_emits_short_message_in_complete() {
        let b = StubBinding::empty();
        *b.uninstall_result.lock().unwrap() = Some(Ok(()));
        let result = compute(
            &shell(),
            &["uninstall", "/p1/system/compute/processes/abc"],
            &b,
            drive,
        )
        .unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let _ = rx.try_recv().unwrap();
                let c = drive_recv(&mut rx).unwrap();
                match c {
                    DispatchChunk::Complete(s) => {
                        assert!(s.starts_with("uninstalled:"));
                        assert!(s.contains("/abc"));
                    }
                    other => panic!("expected Complete, got {:?}", other),
                }
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    // ---------- list ----------

    #[test]
    fn list_empty_streams_empty_listing() {
        let b = StubBinding::empty();
        match compute(&shell(), &["list"], &b, drive).unwrap() {
            VerbOutput::Dispatch(mut rx) => match drive_recv(&mut rx).unwrap() {
                DispatchChunk::Complete(s) => {
                    assert!(s.contains("installed subgraphs (0)"));
                }
                other => panic!("expected Complete, got {:?}", other),
            },
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn list_populated_renders_one_row_per_subgraph() {
        let b = StubBinding {
            list_result: vec![
                (
                    "/p1/system/compute/processes/abc".into(),
                    "/p1/app/x".into(),
                    "active".into(),
                ),
                (
                    "/p1/system/compute/processes/def".into(),
                    "/p1/app/y".into(),
                    "active".into(),
                ),
            ],
            ..StubBinding::empty()
        };
        match compute(&shell(), &["list"], &b, drive).unwrap() {
            VerbOutput::Dispatch(mut rx) => match drive_recv(&mut rx).unwrap() {
                DispatchChunk::Complete(s) => {
                    assert!(s.contains("installed subgraphs (2)"));
                    assert!(s.contains("/abc"));
                    assert!(s.contains("/p1/app/x"));
                    assert!(s.contains("active"));
                }
                other => panic!("expected Complete, got {:?}", other),
            },
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    // ---------- show ----------

    #[test]
    fn show_missing_path_returns_usage() {
        let b = StubBinding::empty();
        let err = compute(&shell(), &["show"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn show_no_subgraph_at_path_emits_failed_usage_with_path() {
        let b = StubBinding::empty();
        match compute(
            &shell(),
            &["show", "/p1/system/compute/processes/missing"],
            &b,
            drive,
        )
        .unwrap()
        {
            VerbOutput::Dispatch(mut rx) => match drive_recv(&mut rx).unwrap() {
                DispatchChunk::Failed(err) => {
                    assert_eq!(err.code, crate::result::ErrorCode::Usage);
                    assert!(err.message.contains("/missing"));
                }
                other => panic!("expected Failed, got {:?}", other),
            },
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn show_streams_rows_from_binding() {
        let b = StubBinding {
            show_result: Some(vec![
                (
                    "subgraph".into(),
                    "/p1/system/compute/processes/abc".into(),
                ),
                ("root expression".into(), "/p1/app/x".into()),
                ("status".into(), "active".into()),
            ]),
            ..StubBinding::empty()
        };
        match compute(
            &shell(),
            &["show", "/p1/system/compute/processes/abc"],
            &b,
            drive,
        )
        .unwrap()
        {
            VerbOutput::Dispatch(mut rx) => match drive_recv(&mut rx).unwrap() {
                DispatchChunk::Complete(s) => {
                    assert!(s.contains("subgraph"));
                    assert!(s.contains("active"));
                }
                other => panic!("expected Complete, got {:?}", other),
            },
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    // ---------- top-level dispatch ----------

    #[test]
    fn compute_without_subcommand_returns_usage() {
        let b = StubBinding::empty();
        let err = compute(&shell(), &[], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn compute_unknown_subcommand_returns_unknown() {
        let b = StubBinding::empty();
        let err = compute(&shell(), &["bogus"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Unknown);
    }
}
