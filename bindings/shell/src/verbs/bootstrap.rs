//! `bootstrap [--threshold N] [--label X]`,
//! `bootstrap status`, `bootstrap export`, `bootstrap import <hex>` —
//! identity-stack ceremony + portable bundle.
//!
//! Wraps `PeerBinding::bootstrap_identity`, `bootstrap_status`,
//! `export_identity_bundle`, `restore_identity_bundle`. Each is a thin
//! formatter; the embedding owns the SDK calls and converts results
//! into the binding's stringly-typed return shapes — see the
//! shell verb guide §8.
//!
//! Subcommand parsing follows the `peer.rs` pattern with one twist:
//! `bootstrap` with no subcommand runs the ceremony (with optional
//! `--threshold` / `--label` flags). `bootstrap status` / `export` /
//! `import` are explicit subcommands. Anything else is an unknown-
//! subcommand error.
//!
//! Hex codec for `bootstrap export` / `import` is lowercase, no
//! separators, no envelope marker. Decoding strips whitespace + an
//! optional `0x` prefix defensively.

use tokio::sync::mpsc;

use crate::binding::PeerBinding;
use crate::result::{
    DispatchChunk, InfoRow, ShellError, VerbOutput,
};
use crate::runtime::BoxFuture;
use crate::shell::Shell;

/// Verb-parser (§8.1). Top-level router. No subcommand → run the
/// ceremony (with optional `--threshold` / `--label` flags). Explicit
/// subcommands route to their per-op handlers.
pub fn bootstrap<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    match args.first().copied() {
        None => bootstrap_ceremony(shell, &[], binding, spawn),
        Some("status") => Ok(status_op(shell.peer_id(), binding)),
        Some("export") => Ok(export_op(shell.peer_id(), binding)),
        Some("import") => import(shell, &args[1..], binding, spawn),
        Some(first) if first.starts_with("--") => {
            bootstrap_ceremony(shell, args, binding, spawn)
        }
        Some(other) => Err(ShellError::unknown(format!(
            "bootstrap: unknown subcommand '{}'. Try: (no-arg ceremony), status, export, import.",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// bootstrap [--threshold N] [--label X]
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Run the identity bootstrap ceremony and stream the
/// outcome. Embeddings can call directly with already-parsed flags.
pub fn bootstrap_op<S>(
    binding: &dyn PeerBinding,
    peer_id: &str,
    threshold: usize,
    label: Option<String>,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<DispatchChunk>(2);
    let label_disp = label
        .as_deref()
        .map(|l| format!(" \"{}\"", l))
        .unwrap_or_default();
    let _ = tx.try_send(DispatchChunk::Dispatched(format!(
        "→ bootstrap (threshold={}){}",
        threshold, label_disp
    )));

    let fut = binding.bootstrap_identity(peer_id, threshold, label);
    let task = Box::pin(async move {
        let chunk = match fut.await {
            Ok(rows) => DispatchChunk::Complete(render_labeled_rows(&rows)),
            Err(e) => DispatchChunk::Failed(ShellError::dispatch(format!(
                "✗ bootstrap → {}",
                e
            ))),
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Dispatch(rx)
}

fn bootstrap_ceremony<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let mut threshold: usize = 1;
    let mut label: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--threshold" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    ShellError::usage("bootstrap: --threshold needs a number")
                })?;
                threshold = v.parse::<usize>().map_err(|_| {
                    ShellError::usage(format!(
                        "bootstrap: --threshold value '{}' is not a non-negative integer",
                        v
                    ))
                })?;
                i += 2;
            }
            "--label" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    ShellError::usage("bootstrap: --label needs a value")
                })?;
                label = Some((*v).to_string());
                i += 2;
            }
            other => {
                return Err(ShellError::usage(format!(
                    "bootstrap: unknown arg '{}'",
                    other
                )));
            }
        }
    }
    Ok(bootstrap_op(
        binding,
        shell.peer_id(),
        threshold,
        label,
        spawn,
    ))
}

// ---------------------------------------------------------------------------
// bootstrap status                       (sync L0)
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Sync status read — `Info` rows from the binding.
pub fn status_op(peer_id: &str, binding: &dyn PeerBinding) -> VerbOutput {
    let rows = binding.bootstrap_status(peer_id);
    VerbOutput::Info(
        rows.into_iter()
            .map(|(label, value)| InfoRow::labeled(label, value))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// bootstrap export                       (sync; produces hex)
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Export the identity bundle and render as a sized
/// hex Message. Failure surfaces as `ShellError::dispatch` since the
/// binding call is synchronous.
pub fn export_op(peer_id: &str, binding: &dyn PeerBinding) -> VerbOutput {
    match binding.export_identity_bundle(peer_id) {
        Ok(bytes) => VerbOutput::Message(format!(
            "bundle: {} bytes\n{}",
            bytes.len(),
            encode_hex(&bytes)
        )),
        // The verb-parser's signature is Result<VerbOutput, ShellError>;
        // here in the op we render a Message inline since the caller
        // path is sync. Errors stringify into a Message prefixed with
        // "bootstrap export:" so the user sees the failure verbatim
        // without a separate error rendering — matches the existing
        // sync-error-as-message pattern used by `disconnect` etc.
        Err(e) => VerbOutput::Message(format!("bootstrap export: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// bootstrap import <hex>                 (async)
// ---------------------------------------------------------------------------

/// Verb-op (§8.1). Decode `hex_bundle`, restore, and stream the
/// outcome. Bad hex is reported as a parse failure inside the Dispatch
/// stream so the verb-parser can stay infallible past arg-presence
/// check.
pub fn import_op<S>(
    binding: &dyn PeerBinding,
    peer_id: &str,
    hex_bundle: String,
    spawn: S,
) -> VerbOutput
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let (tx, rx) = mpsc::channel::<DispatchChunk>(2);
    let _ = tx.try_send(DispatchChunk::Dispatched(
        "→ bootstrap import".into(),
    ));

    let bytes = match decode_hex(&hex_bundle) {
        Ok(b) => b,
        Err(msg) => {
            let _ = tx.try_send(DispatchChunk::Failed(ShellError::usage(format!(
                "bootstrap import: bad hex — {}",
                msg
            ))));
            // Producer task never runs; channel-close on drop signals
            // dispatch complete.
            return VerbOutput::Dispatch(rx);
        }
    };

    let fut = binding.restore_identity_bundle(peer_id, bytes);
    let task = Box::pin(async move {
        let chunk = match fut.await {
            Ok(rows) => DispatchChunk::Complete(render_labeled_rows(&rows)),
            Err(e) => DispatchChunk::Failed(ShellError::dispatch(format!(
                "✗ bootstrap import → {}",
                e
            ))),
        };
        let _ = tx.send(chunk).await;
    });
    spawn(task);
    VerbOutput::Dispatch(rx)
}

fn import<S>(
    shell: &Shell,
    args: &[&str],
    binding: &dyn PeerBinding,
    spawn: S,
) -> Result<VerbOutput, ShellError>
where
    S: FnOnce(BoxFuture<'static, ()>),
{
    let hex = args
        .first()
        .ok_or_else(|| ShellError::usage("bootstrap import: usage: bootstrap import <hex>"))?;
    Ok(import_op(
        binding,
        shell.peer_id(),
        (*hex).to_string(),
        spawn,
    ))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Lowercase hex, no separators. Two chars per byte.
fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Strip whitespace + leading `0x`/`0X`; require an even number of
/// remaining nybbles; decode lowercase or uppercase. Returns a
/// human-facing message on the error path.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let body = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if body.is_empty() {
        return Err("input is empty".into());
    }
    if !body.len().is_multiple_of(2) {
        return Err("odd number of nybbles".into());
    }
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(body.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nybble(bytes[i])?;
        let lo = hex_nybble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nybble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("non-hex character '{}'", c as char)),
    }
}

/// Render labeled rows as a 2-space-indented `"  label: value"` block
/// for use as a `DispatchChunk::Complete` body — matches the bootstrap
/// outcome shape in the guide §8.
fn render_labeled_rows(rows: &[(String, String)]) -> String {
    rows.iter()
        .map(|(l, v)| format!("  {}: {}", l, v))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{EntityRead, TreeListingEntry};
    use std::sync::Mutex;

    type RowsResult = Result<Vec<(String, String)>, String>;

    struct StubBinding {
        bootstrap_result: Mutex<Option<RowsResult>>,
        status_result: Vec<(String, String)>,
        export_result: Mutex<Option<Result<Vec<u8>, String>>>,
        restore_result: Mutex<Option<RowsResult>>,
        last_threshold: Mutex<Option<usize>>,
        last_label: Mutex<Option<Option<String>>>,
    }

    impl StubBinding {
        fn empty() -> Self {
            Self {
                bootstrap_result: Mutex::new(None),
                status_result: Vec::new(),
                export_result: Mutex::new(None),
                restore_result: Mutex::new(None),
                last_threshold: Mutex::new(None),
                last_label: Mutex::new(None),
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

        fn bootstrap_identity(
            &self,
            _peer_id: &str,
            threshold: usize,
            label: Option<String>,
        ) -> BoxFuture<'static, Result<Vec<(String, String)>, String>> {
            *self.last_threshold.lock().unwrap() = Some(threshold);
            *self.last_label.lock().unwrap() = Some(label);
            let r = self
                .bootstrap_result
                .lock()
                .unwrap()
                .clone()
                .expect("test setup forgot to populate bootstrap_result");
            Box::pin(async move { r })
        }

        fn bootstrap_status(&self, _peer_id: &str) -> Vec<(String, String)> {
            self.status_result.clone()
        }

        fn export_identity_bundle(
            &self,
            _peer_id: &str,
        ) -> Result<Vec<u8>, String> {
            self.export_result
                .lock()
                .unwrap()
                .clone()
                .expect("test setup forgot to populate export_result")
        }

        fn restore_identity_bundle(
            &self,
            _peer_id: &str,
            _bytes: Vec<u8>,
        ) -> BoxFuture<'static, Result<Vec<(String, String)>, String>> {
            let r = self
                .restore_result
                .lock()
                .unwrap()
                .clone()
                .expect("test setup forgot to populate restore_result");
            Box::pin(async move { r })
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

    // ---------- ceremony ----------

    #[test]
    fn no_args_runs_default_ceremony() {
        let b = StubBinding::empty();
        *b.bootstrap_result.lock().unwrap() = Some(Ok(vec![
            ("status".into(), "bootstrapped".into()),
            ("identity".into(), "abc1234".into()),
        ]));
        let result = bootstrap(&shell(), &[], &b, drive).unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let _ = rx.try_recv().unwrap();
                let c = drive_recv(&mut rx).unwrap();
                match c {
                    DispatchChunk::Complete(s) => {
                        assert!(s.contains("bootstrapped"));
                        assert!(s.contains("abc1234"));
                    }
                    other => panic!("expected Complete, got {:?}", other),
                }
            }
            other => panic!("unexpected variant: {:?}", other),
        }
        assert_eq!(*b.last_threshold.lock().unwrap(), Some(1));
        assert_eq!(*b.last_label.lock().unwrap(), Some(None));
    }

    #[test]
    fn threshold_flag_parses() {
        let b = StubBinding::empty();
        *b.bootstrap_result.lock().unwrap() = Some(Err("multi_signer_unsupported".into()));
        let _ = bootstrap(&shell(), &["--threshold", "2"], &b, drive).unwrap();
        assert_eq!(*b.last_threshold.lock().unwrap(), Some(2));

        let err = bootstrap(&shell(), &["--threshold"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);

        let err = bootstrap(&shell(), &["--threshold", "abc"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn label_flag_parses() {
        let b = StubBinding::empty();
        *b.bootstrap_result.lock().unwrap() = Some(Ok(vec![("status".into(), "ok".into())]));
        let _ = bootstrap(&shell(), &["--label", "my-quorum"], &b, drive).unwrap();
        assert_eq!(
            *b.last_label.lock().unwrap(),
            Some(Some("my-quorum".into()))
        );

        let err = bootstrap(&shell(), &["--label"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn unknown_positional_returns_unknown() {
        let b = StubBinding::empty();
        let err = bootstrap(&shell(), &["bogus"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Unknown);
    }

    #[test]
    fn multi_signer_error_surfaces_in_failed_chunk() {
        let b = StubBinding::empty();
        *b.bootstrap_result.lock().unwrap() = Some(Err(
            "multi_signer_unsupported — quorum_threshold = 2 ...".into(),
        ));
        let result =
            bootstrap(&shell(), &["--threshold", "2"], &b, drive).unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let _ = rx.try_recv().unwrap();
                let c = drive_recv(&mut rx).unwrap();
                match c {
                    DispatchChunk::Failed(err) => {
                        assert!(err.message.contains("multi_signer_unsupported"));
                    }
                    other => panic!("expected Failed, got {:?}", other),
                }
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    // ---------- status ----------

    #[test]
    fn status_when_not_bootstrapped_returns_single_row() {
        let b = StubBinding {
            status_result: vec![("bootstrapped".into(), "false".into())],
            ..StubBinding::empty()
        };
        match bootstrap(&shell(), &["status"], &b, |_| {}).unwrap() {
            VerbOutput::Info(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].label.as_deref(), Some("bootstrapped"));
                assert_eq!(rows[0].value, "false");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn status_when_bootstrapped_returns_multi_row() {
        let b = StubBinding {
            status_result: vec![
                ("bootstrapped".into(), "true".into()),
                ("identity".into(), "abc1234".into()),
                ("quorum".into(), "def5678".into()),
                ("peer config".into(), "/p1/system/identity/peer-config".into()),
            ],
            ..StubBinding::empty()
        };
        match bootstrap(&shell(), &["status"], &b, |_| {}).unwrap() {
            VerbOutput::Info(rows) => {
                assert_eq!(rows.len(), 4);
                assert_eq!(rows[0].value, "true");
                assert_eq!(rows[2].label.as_deref(), Some("quorum"));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    // ---------- export ----------

    #[test]
    fn export_success_returns_hex_message_with_size() {
        let b = StubBinding::empty();
        *b.export_result.lock().unwrap() = Some(Ok(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        match bootstrap(&shell(), &["export"], &b, |_| {}).unwrap() {
            VerbOutput::Message(s) => {
                assert!(s.starts_with("bundle: 4 bytes"));
                assert!(s.contains("deadbeef"));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn export_error_surfaces_as_message() {
        let b = StubBinding::empty();
        *b.export_result.lock().unwrap() = Some(Err("not_bootstrapped".into()));
        match bootstrap(&shell(), &["export"], &b, |_| {}).unwrap() {
            VerbOutput::Message(s) => {
                assert!(s.contains("not_bootstrapped"));
                assert!(s.starts_with("bootstrap export:"));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    // ---------- import ----------

    #[test]
    fn import_missing_arg_returns_usage() {
        let b = StubBinding::empty();
        let err = bootstrap(&shell(), &["import"], &b, |_| {}).unwrap_err();
        assert_eq!(err.code, crate::result::ErrorCode::Usage);
    }

    #[test]
    fn import_bad_hex_emits_failed_chunk() {
        let b = StubBinding::empty();
        let result = bootstrap(&shell(), &["import", "xyz!"], &b, drive).unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let _ = rx.try_recv().unwrap();
                let chunk = rx.try_recv().expect("Failed should be queued sync");
                match chunk {
                    DispatchChunk::Failed(err) => {
                        assert_eq!(err.code, crate::result::ErrorCode::Usage);
                        assert!(err.message.contains("bad hex"));
                    }
                    other => panic!("expected Failed, got {:?}", other),
                }
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn import_success_streams_dispatched_then_complete() {
        let b = StubBinding::empty();
        *b.restore_result.lock().unwrap() = Some(Ok(vec![
            ("restored".into(), "true".into()),
            ("identity".into(), "abc1234".into()),
        ]));
        let result =
            bootstrap(&shell(), &["import", "deadbeef"], &b, drive).unwrap();
        match result {
            VerbOutput::Dispatch(mut rx) => {
                let _ = rx.try_recv().unwrap();
                let c = drive_recv(&mut rx).unwrap();
                match c {
                    DispatchChunk::Complete(s) => {
                        assert!(s.contains("restored"));
                        assert!(s.contains("abc1234"));
                    }
                    other => panic!("expected Complete, got {:?}", other),
                }
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    // ---------- hex codec ----------

    #[test]
    fn hex_codec_round_trips_arbitrary_bytes() {
        let bytes = vec![0x00, 0x01, 0x10, 0xFF, 0xA5, 0x5A];
        let s = encode_hex(&bytes);
        assert_eq!(s, "0001 10ffa55a".replace(' ', ""));
        let back = decode_hex(&s).unwrap();
        assert_eq!(back, bytes);
    }

    #[test]
    fn hex_decode_tolerates_whitespace_and_0x_prefix() {
        assert_eq!(
            decode_hex(" 0xDE AD BE EF\n").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(
            decode_hex("0XDeadBeef").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn hex_decode_rejects_odd_length_and_non_hex() {
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("xy").is_err());
        assert!(decode_hex("").is_err());
    }
}
