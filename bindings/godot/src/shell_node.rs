//! EntityShell — a Godot RefCounted wrapping `entity_shell::Shell`.
//!
//! Godot consumer of the `entity-shell` crate. GDScript-facing surface
//! is a single `dispatch(line)` method that runs the raw command line
//! through the crate's `entity_shell::dispatcher::dispatch` entry
//! point. The crate ships 19 verbs:
//!
//! - Tree / session (sync): pwd, cd, ls, cat, tree, info, help,
//!   disconnect, put, rm (+remove alias). Working hands-on.
//! - Async streaming: connect, exec, query, count. Route through
//!   dispatch but render the streaming-not-supported placeholder
//!   until a tick-driven receiver drain into the panel scrollback
//!   lands (own adoption slice).
//! - Lifecycle (require `AppActionSink`): peer, peers, open, tail,
//!   tails, untail. Godot has no peer-management / window-spawn /
//!   subscription-tail infrastructure today; we pass the no-op
//!   `impl AppActionSink for ()` so these verbs degrade gracefully
//!   per their crate-side defaults. Wire a real `AppActionSink`
//!   when the Godot embedding grows lifecycle ops of its own.
//!
//! Construction: `EntityShell.new_for_peer(peer: EntityPeer)` from
//! GDScript. The shell holds a `Gd<EntityPeer>` handle (Godot's
//! non-owning Node reference) so the `PeerBinding` impl can read the
//! peer's `PeerContext` on each trait method call.
//!
//! Rich `VerbOutput` variants (`Listing`, `Entity`, `Tree`, `Info`)
//! are rendered to text by `render_output` so the existing scrollback-
//! style shell panel works uniformly. A future type-aware renderer
//! (entity inspector for `cat`, tree widget for `tree`, etc.) can
//! consume the typed variants directly via a richer FFI surface when
//! we want it.

use godot::prelude::*;
use tokio::sync::mpsc;

use entity_shell::{
    DispatchChunk, EntityRead, PeerBinding, Shell, ShellError, StreamChunk,
    TreeListingEntry, VerbOutput, EntityView, InfoRow, ListingSection, TreeView,
};

use crate::peer_node::EntityPeer;

/// An in-flight async verb producing chunks on a receiver. Held by
/// `EntityShell.active_streams` between the dispatch that created it
/// and the eventual `tick()` calls that drain it. Channel-close
/// (`TryRecvError::Disconnected`) signals stream completion; the
/// stream is then dropped from the active list.
enum ActiveStream {
    Lines(mpsc::Receiver<StreamChunk>),
    Dispatch(mpsc::Receiver<DispatchChunk>),
}

/// `PeerBinding` impl backed by a held `Gd<EntityPeer>` handle. Each
/// trait method binds the peer, reads through `PeerContext`, and
/// returns owned values per the crate's contract.
///
/// Constructed fresh per verb dispatch from `EntityShell` — does not
/// outlive a single verb call, so the borrow into the peer node is
/// safe as long as the peer hasn't been freed (the shell panel owns
/// the peer reference and is destroyed before the peer).
struct GodotPeerBinding {
    peer_id: String,
    peer_node: Gd<EntityPeer>,
}

impl PeerBinding for GodotPeerBinding {
    fn peer_id(&self) -> &str {
        &self.peer_id
    }

    fn primary_peer_id(&self) -> String {
        self.peer_id.clone()
    }

    fn peer_ids(&self) -> Vec<String> {
        vec![self.peer_id.clone()]
    }

    fn connected_peers(&self) -> Vec<String> {
        // Godot has no connection registry yet — deferred until the
        // multi-peer + remote-connection story lands. Empty here means
        // alias resolution can't find connected remotes by label; the
        // four reserved aliases (`@self`/`@primary`/`@system`/`@default`)
        // still resolve to the bound peer.
        Vec::new()
    }

    fn peer_label(&self, _peer_id: &str) -> Option<String> {
        // No peer-label store yet on the Godot side.
        None
    }

    fn tree_listing(&self, peer_id: &str, prefix: &str) -> Vec<TreeListingEntry> {
        let peer = self.peer_node.bind();
        let Some(ctx) = peer.peer_ctx() else {
            return Vec::new();
        };
        // Single-peer scope: ignore `peer_id` arg if it matches the
        // bound peer; if not, we have nothing to return (no multi-peer
        // routing yet).
        if peer_id != self.peer_id {
            return Vec::new();
        }
        ctx.store()
            .list(prefix)
            .into_iter()
            .map(|e| TreeListingEntry { path: e.path })
            .collect()
    }

    fn get_entity(&self, peer_id: &str, path: &str) -> Option<EntityRead> {
        let peer = self.peer_node.bind();
        let ctx = peer.peer_ctx()?;
        if peer_id != self.peer_id {
            return None;
        }
        ctx.store().get(path).map(|e| EntityRead {
            entity_type: e.entity_type.clone(),
            data: e.data.clone(),
            content_hash: e.content_hash.to_string(),
        })
    }

    fn put_entity(
        &self,
        peer_id: &str,
        path: &str,
        entity_type: &str,
        params_text: Option<String>,
    ) -> Result<(), String> {
        if peer_id != self.peer_id {
            return Err(format!(
                "put: wrong peer (bound to {}, got {})",
                self.peer_id, peer_id
            ));
        }
        // JSON-body parsing is the embedding's concern per the trait
        // contract. Godot punts on it for the same reason as exec —
        // serde_json adoption is a separate slice. `put <path> <type>`
        // without a body writes an empty entity; `put ... <json>`
        // errors with a clear message.
        if params_text.is_some() {
            return Err(
                "put: JSON body parsing not yet supported by Godot binding \
                 (use `put <path> <type>` without a body for now)"
                    .into(),
            );
        }
        let peer = self.peer_node.bind();
        let Some(ctx) = peer.peer_ctx() else {
            return Err("put: peer not started".into());
        };
        // `Entity::new` rejects empty bodies, so an empty `put` writes
        // a single-byte CBOR null (`0xF6`) — valid CBOR, smallest legal
        // body, parses to nothing meaningful. When JSON-body support
        // lands the embedding-side parser will replace this with the
        // serialized CBOR.
        let entity = entity_entity::Entity::new(entity_type, vec![0xF6])
            .map_err(|e| format!("put: entity construct failed: {}", e))?;
        ctx.store()
            .put(path, entity)
            .map_err(|e| format!("put: store write failed: {}", e))?;
        Ok(())
    }

    fn remove_entity(&self, peer_id: &str, path: &str) {
        if peer_id != self.peer_id {
            return;
        }
        let peer = self.peer_node.bind();
        let Some(ctx) = peer.peer_ctx() else {
            return;
        };
        let _ = ctx.store().remove(path);
    }

    // primary_arm: defaults to "local" — matches Godot's single-peer
    // direct-attachment story. Override later when multi-arm transport
    // appears on the Godot side.

    // remove_connection: defaults to no-op — disconnect's pre-check
    // against connected_peers (which we return empty) means the verb
    // reports "no action" without ever calling this.

    // connect_peer / execute / query / count: default to error
    // returns. Async wiring (closure spawner against Godot's tokio
    // runtime + tick-driven streaming UI) is its own adoption slice.
    // Until then the user-facing dispatch returns a "(streaming
    // output not yet supported)" placeholder via render_output.

    // -----------------------------------------------------------------
    // Compute + Identity bridge (REQUEST-BINDING-PARITY-SWEEP-PHASE-1 §2.16)
    // -----------------------------------------------------------------
    //
    // Same shape as the eGUI reference impl
    // (`egui-entity-core-rust/src/views/shell/binding.rs:227+`). Each
    // method extracts an `Arc<PeerContext>` from the peer-node bind
    // guard, drops the guard, and spawns an async block owning the
    // Arc — the SDK methods return `'static + Send` futures so this
    // composes cleanly. The single-peer scope means we hand back
    // "not bound to this peer" for off-peer requests.

    fn compute_eval(
        &self,
        peer_id: &str,
        expr_path: String,
        budget: Option<u64>,
    ) -> entity_shell::runtime::BoxFuture<'static, Result<String, String>> {
        if peer_id != self.peer_id {
            let bound = self.peer_id.clone();
            let got = peer_id.to_string();
            return Box::pin(async move {
                Err(format!("compute eval: wrong peer (bound to {}, got {})", bound, got))
            });
        }
        let Some(ctx) = self.peer_node.bind().peer_ctx_arc() else {
            return Box::pin(async move { Err("compute eval: peer not started".into()) });
        };
        let fut = ctx.compute().eval(expr_path, entity_sdk::compute::EvalOptions { budget });
        Box::pin(async move {
            fut.await
                .map(format_compute_eval_result)
                .map_err(|e| e.to_string())
        })
    }

    fn compute_install(
        &self,
        peer_id: &str,
        root_expression_path: String,
        result_path: Option<String>,
    ) -> entity_shell::runtime::BoxFuture<'static, Result<(String, String), String>> {
        if peer_id != self.peer_id {
            return Box::pin(async move { Err("compute install: wrong peer".into()) });
        }
        let Some(ctx) = self.peer_node.bind().peer_ctx_arc() else {
            return Box::pin(async move { Err("compute install: peer not started".into()) });
        };
        let fut = ctx
            .compute()
            .install(root_expression_path, entity_sdk::compute::InstallOptions { result_path });
        Box::pin(async move {
            fut.await
                .map(|r| (r.subgraph_path, r.result_path))
                .map_err(|e| e.to_string())
        })
    }

    fn compute_uninstall(
        &self,
        peer_id: &str,
        subgraph_path: String,
    ) -> entity_shell::runtime::BoxFuture<'static, Result<(), String>> {
        if peer_id != self.peer_id {
            return Box::pin(async move { Err("compute uninstall: wrong peer".into()) });
        }
        let Some(ctx) = self.peer_node.bind().peer_ctx_arc() else {
            return Box::pin(async move { Err("compute uninstall: peer not started".into()) });
        };
        let fut = ctx.compute().uninstall(subgraph_path);
        Box::pin(async move { fut.await.map_err(|e| e.to_string()) })
    }

    // `compute_list` / `compute_show` are async on the trait so the Worker
    // arm can satisfy them via an L1 query / on-demand Get. The SDK's
    // `ComputeOps::{list,show}` are synchronous local-tree walks, so the
    // Direct (Godot) arm resolves immediately: compute the owned rows under
    // the bind guard, drop it, and hand back a ready future. Off-peer /
    // not-started stays lenient (`Ok(empty)` / `Ok(None)`) — matching the
    // prior sync behavior and the trait defaults.
    fn compute_list(
        &self,
        peer_id: &str,
    ) -> entity_shell::runtime::BoxFuture<'static, Result<Vec<(String, String, String)>, String>>
    {
        if peer_id != self.peer_id {
            return Box::pin(async move { Ok(Vec::new()) });
        }
        let rows = match self.peer_node.bind().peer_ctx() {
            Some(ctx) => ctx
                .compute()
                .list()
                .into_iter()
                .map(|s| (s.subgraph_path, s.root_expression_path, s.status))
                .collect(),
            None => Vec::new(),
        };
        Box::pin(async move { Ok(rows) })
    }

    fn compute_show(
        &self,
        peer_id: &str,
        subgraph_path: String,
    ) -> entity_shell::runtime::BoxFuture<'static, Result<Option<Vec<(String, String)>>, String>>
    {
        if peer_id != self.peer_id {
            return Box::pin(async move { Ok(None) });
        }
        let rows = self.peer_node.bind().peer_ctx().and_then(|ctx| {
            let s = ctx.compute().show(&subgraph_path)?;
            Some(vec![
                ("subgraph".into(), s.subgraph_path),
                ("root expression".into(), s.root_expression_path),
                ("result path".into(), s.result_path),
                ("status".into(), s.status),
                ("installed by".into(), short_hash(&s.installed_by)),
                ("installation grant".into(), short_hash(&s.installation_grant)),
            ])
        });
        Box::pin(async move { Ok(rows) })
    }

    fn bootstrap_identity(
        &self,
        peer_id: &str,
        threshold: usize,
        label: Option<String>,
    ) -> entity_shell::runtime::BoxFuture<'static, Result<Vec<(String, String)>, String>> {
        if peer_id != self.peer_id {
            return Box::pin(async move { Err("bootstrap: wrong peer".into()) });
        }
        let Some(ctx) = self.peer_node.bind().peer_ctx_arc() else {
            return Box::pin(async move { Err("bootstrap: peer not started".into()) });
        };
        let opts = entity_sdk::identity_bootstrap::BootstrapOptions {
            quorum_threshold: threshold,
            additional_signers: vec![],
            label,
            properties: vec![],
            force: false,
        };
        let fut = ctx.identity().bootstrap(opts);
        Box::pin(async move {
            fut.await
                .map(format_bootstrap_result)
                .map_err(|e| e.to_string())
        })
    }

    fn bootstrap_status(&self, peer_id: &str) -> Vec<(String, String)> {
        if peer_id != self.peer_id {
            return Vec::new();
        }
        let peer = self.peer_node.bind();
        let Some(ctx) = peer.peer_ctx() else {
            return Vec::new();
        };
        let s = ctx.identity().bootstrap_status();
        let mut rows = vec![
            ("bootstrapped".into(), s.bootstrapped.to_string()),
            ("identity".into(), short_hash(&s.identity_hash)),
        ];
        if let Some(q) = s.quorum_id {
            rows.push(("quorum".into(), short_hash(&q)));
        }
        if let Some(p) = s.peer_config_path {
            rows.push(("peer config".into(), p));
        }
        rows
    }

    fn export_identity_bundle(&self, peer_id: &str) -> Result<Vec<u8>, String> {
        if peer_id != self.peer_id {
            return Err("bootstrap export: wrong peer".into());
        }
        let peer = self.peer_node.bind();
        let ctx = peer
            .peer_ctx()
            .ok_or_else(|| "bootstrap export: peer not started".to_string())?;
        let bundle = ctx.identity().export_bundle().map_err(|e| e.to_string())?;
        bundle.to_cbor().map_err(|e| e.to_string())
    }

    fn restore_identity_bundle(
        &self,
        peer_id: &str,
        bundle_cbor: Vec<u8>,
    ) -> entity_shell::runtime::BoxFuture<'static, Result<Vec<(String, String)>, String>> {
        if peer_id != self.peer_id {
            return Box::pin(async move { Err("bootstrap import: wrong peer".into()) });
        }
        let bundle = match entity_sdk::identity_bundle::IdentityBundle::from_cbor(&bundle_cbor) {
            Ok(b) => b,
            Err(e) => return Box::pin(async move { Err(format!("bundle decode: {}", e)) }),
        };
        let Some(ctx) = self.peer_node.bind().peer_ctx_arc() else {
            return Box::pin(async move { Err("bootstrap import: peer not started".into()) });
        };
        let fut = ctx.identity().restore_from_bundle(&bundle);
        Box::pin(async move {
            fut.await
                .map(format_bootstrap_result)
                .map_err(|e| e.to_string())
        })
    }
}

fn short_hash(h: &entity_hash::Hash) -> String {
    let hex: String = h
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    if hex.len() >= 8 {
        format!("{}…{}", &hex[..4], &hex[hex.len() - 4..])
    } else {
        hex
    }
}

fn format_compute_eval_result(r: entity_sdk::compute::ComputeEvalResult) -> String {
    use entity_sdk::compute::ComputeValue;
    let v = match &r.value {
        ComputeValue::Null => "Null".to_string(),
        ComputeValue::Bool(b) => format!("Bool({})", b),
        ComputeValue::Int(n) => format!("Int({})", n),
        ComputeValue::Uint(n) => format!("Uint({})", n),
        ComputeValue::Float(f) => format!("Float({})", f),
        ComputeValue::Bytes(b) => format!("Bytes({} bytes)", b.len()),
        ComputeValue::Text(s) => format!("Text({:?})", s),
        ComputeValue::Hash(h) => format!("Hash({})", short_hash(h)),
        ComputeValue::Array(a) => format!("Array({} elems)", a.len()),
        ComputeValue::Map(m) => format!("Map({} pairs)", m.len()),
        ComputeValue::Entity(e) => format!("Entity({})", e.entity_type),
        ComputeValue::Closure(e) => format!("Closure({})", e.entity_type),
        ComputeValue::Error(e) => format!("Error({})", e.entity_type),
    };
    format!(
        "  value: {}\n  entity type: {}",
        v, r.result_entity.entity_type
    )
}

fn format_bootstrap_result(r: entity_sdk::identity_bootstrap::BootstrapResult) -> Vec<(String, String)> {
    use entity_sdk::identity_bootstrap::BootstrapResult::*;
    match r {
        AlreadyBootstrapped { identity_hash, quorum_id } => vec![
            ("status".into(), "already bootstrapped".into()),
            ("identity".into(), short_hash(&identity_hash)),
            ("quorum".into(), short_hash(&quorum_id)),
        ],
        Bootstrapped {
            identity_hash,
            quorum_id,
            controller_cert,
            peer_config_path,
            issued_caps,
        } => {
            let mut rows = vec![
                ("status".into(), "bootstrapped".into()),
                ("identity".into(), short_hash(&identity_hash)),
                ("quorum".into(), short_hash(&quorum_id)),
                ("controller cert".into(), short_hash(&controller_cert)),
                ("peer config".into(), peer_config_path),
            ];
            if !issued_caps.is_empty() {
                rows.push((
                    "issued caps".into(),
                    issued_caps
                        .iter()
                        .map(short_hash)
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
            }
            rows
        }
    }
}

/// Shell session bound to a peer. One per shell panel instance. Holds
/// the `entity_shell::Shell` session state, a `Gd<EntityPeer>` handle
/// for binding-side tree reads, and any active async-verb receivers
/// awaiting drain by the panel's `_process` tick.
#[derive(GodotClass)]
#[class(no_init, base=RefCounted)]
pub struct EntityShell {
    base: Base<RefCounted>,
    shell: Shell,
    peer_node: Gd<EntityPeer>,
    /// Active async-verb streams. Each entry corresponds to one
    /// `connect`/`exec`/`query`/`count` dispatch whose producer task
    /// is running on the peer's tokio runtime. Drained by `tick()`;
    /// removed when the channel closes (verb done).
    active_streams: Vec<ActiveStream>,
}

#[godot_api]
impl EntityShell {
    /// Construct a shell bound to `peer`. wd initializes to
    /// `/{peer_id}/`. The shell holds a reference to the EntityPeer
    /// node so verb dispatch can read its tree state via the
    /// crate-side `PeerBinding` trait.
    #[func]
    fn new_for_peer(peer: Gd<EntityPeer>) -> Gd<Self> {
        // Pull the bound peer_id out via the crate-internal accessor —
        // the `#[func] fn peer_id` exposed to GDScript is not callable
        // from Rust (gdext private-method visibility). Fall back to ""
        // if the peer hasn't been booted yet; the resulting Shell
        // would be near-useless but won't panic.
        let pid = peer
            .bind()
            .peer_ctx()
            .map(|c| c.peer_id().to_string())
            .unwrap_or_default();
        Gd::from_init_fn(|base| Self {
            base,
            shell: Shell::new(pid),
            peer_node: peer,
            active_streams: Vec::new(),
        })
    }

    /// Construct a fresh `GodotPeerBinding` for a single verb call.
    /// Constructed-per-call to match the crate's contract and to avoid
    /// holding the peer-node bind() guard across verb execution.
    fn binding(&self) -> GodotPeerBinding {
        GodotPeerBinding {
            peer_id: self.shell.peer_id().to_string(),
            peer_node: self.peer_node.clone(),
        }
    }

    /// Current working directory.
    #[func]
    fn wd(&self) -> GString {
        GString::from(self.shell.wd())
    }

    /// Bound peer id (read-only).
    #[func]
    fn peer_id(&self) -> GString {
        GString::from(self.shell.peer_id())
    }

    /// Dispatch a raw command line through the crate's dispatcher.
    /// Returns the rendered output as a single `GString` (multi-line
    /// for `ls`/`cat`/`tree`/`info`); errors come back prefixed
    /// `error: `. Returns `"unknown verb: <verb>"` for unrecognized
    /// commands. Empty/whitespace input returns an empty string.
    ///
    /// Async verbs (`connect`, `exec`, `query`, `count`) parse and
    /// dispatch immediately, returning the first pre-queued chunk
    /// (e.g., "→ connecting to ws://...") as the result string and
    /// stashing the receiver in `active_streams`. Subsequent chunks
    /// surface via `tick()` — the panel must call that on its
    /// `_process` to drain them.
    #[func]
    fn dispatch(&mut self, line: GString) -> GString {
        let line_str = line.to_string();
        if line_str.trim().is_empty() {
            return GString::new();
        }
        let binding = self.binding();

        // Real spawner backed by the peer's tokio runtime. Async
        // verbs hand us their producer future; we hand it to the
        // runtime which drives it independently of the Godot main
        // thread. The runtime keeps the future alive until completion;
        // the receiver we capture in `active_streams` is what surfaces
        // its chunks back to GDScript via `tick()`.
        //
        // No runtime → the closure is unreachable for the sync verbs
        // we route, AND the async verbs' default-impl `PeerBinding`
        // methods return immediately-resolving error futures whose
        // chunks land in the receiver before the spawner is even
        // called. So a None handle is recoverable; we substitute a
        // no-op that drops the future (same fallback as the old
        // behavior).
        let runtime = self.peer_node.bind().runtime_handle();
        let spawn = |fut: entity_shell::runtime::BoxFuture<'static, ()>| {
            match &runtime {
                Some(handle) => { handle.spawn(fut); }
                None => { /* drop unrun — see comment above */ }
            }
        };

        let result = entity_shell::dispatcher::dispatch(
            &line_str,
            &mut self.shell,
            &binding,
            None,
            // No AppActionSink: pass the unit-type default-impl so
            // lifecycle verbs (peer, open, tail/tails/untail) degrade
            // gracefully rather than requiring a Godot-side
            // implementation we don't have today.
            &(),
            spawn,
        );

        match result {
            Some(Ok(VerbOutput::Lines(rx))) => {
                self.active_streams.push(ActiveStream::Lines(rx));
                // Verb pre-queues a Dispatched chunk before spawning.
                // We don't drain here (would race the producer task);
                // the panel's first tick after this returns it.
                GString::from("(stream started — chunks arriving)")
            }
            Some(Ok(VerbOutput::Dispatch(rx))) => {
                self.active_streams.push(ActiveStream::Dispatch(rx));
                GString::from("(dispatch started — result pending)")
            }
            Some(verb_result) => dispatch_render(verb_result),
            None => {
                let verb = line_str.split_whitespace().next().unwrap_or("");
                GString::from(&format!("error: unknown verb: {}", verb))
            }
        }
    }

    /// Drain any pending chunks from active async-verb streams.
    /// Returns a `PackedStringArray` of rendered lines ready for the
    /// scrollback. Each line follows the existing convention: error
    /// chunks are prefixed `error: ` so the GDScript panel can color
    /// them red (matching the `dispatch()` error convention); other
    /// chunks are plain text.
    ///
    /// Call from the shell panel's `_process(delta)`. Cheap when no
    /// streams are active (one `is_empty` check).
    #[func]
    fn tick(&mut self) -> PackedStringArray {
        let mut out = PackedStringArray::new();
        if self.active_streams.is_empty() {
            return out;
        }
        // Iterate manually so we can drop completed streams from the
        // vec in the same pass. `retain_mut` would work but obscures
        // the per-chunk emission.
        let mut i = 0;
        while i < self.active_streams.len() {
            let done = drain_stream(&mut self.active_streams[i], &mut out);
            if done {
                self.active_streams.swap_remove(i);
                // Don't increment i — swap_remove brought a new entry
                // to this slot.
            } else {
                i += 1;
            }
        }
        out
    }

    /// True when at least one async verb's stream is still active.
    /// The panel can use this to decide whether to keep calling
    /// `tick()` aggressively or back off.
    #[func]
    fn has_active_streams(&self) -> bool {
        !self.active_streams.is_empty()
    }
}

/// Drain one stream's chunks into `out`. Returns true when the
/// stream's channel has closed (verb done — drop from active list);
/// false when it's still open but empty (try again next tick).
fn drain_stream(stream: &mut ActiveStream, out: &mut PackedStringArray) -> bool {
    use mpsc::error::TryRecvError;
    loop {
        match stream {
            ActiveStream::Lines(rx) => match rx.try_recv() {
                Ok(chunk) => out.push(&render_stream_chunk(chunk)),
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            },
            ActiveStream::Dispatch(rx) => match rx.try_recv() {
                Ok(chunk) => out.push(&render_dispatch_chunk(chunk)),
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            },
        }
    }
}

fn render_stream_chunk(chunk: StreamChunk) -> GString {
    match chunk {
        StreamChunk::Dispatched(s) | StreamChunk::Line(s) | StreamChunk::Complete(s) => {
            GString::from(&s)
        }
        StreamChunk::Failed(e) => GString::from(&format!("error: {}", e.message)),
    }
}

fn render_dispatch_chunk(chunk: DispatchChunk) -> GString {
    match chunk {
        DispatchChunk::Dispatched(s) | DispatchChunk::Progress(s) | DispatchChunk::Complete(s) => {
            GString::from(&s)
        }
        DispatchChunk::Failed(e) => GString::from(&format!("error: {}", e.message)),
    }
}

/// Render a verb result into a single display string for the shell
/// panel's scrollback. Errors come back prefixed with `error: ` so the
/// panel can color them red; success results are rendered per
/// variant.
fn dispatch_render(result: Result<VerbOutput, ShellError>) -> GString {
    match result {
        Ok(out) => GString::from(&render_output(&out)),
        Err(e) => GString::from(&format!("error: {}", e.message)),
    }
}

/// Render a `VerbOutput` variant to a multi-line text block suitable
/// for a scrollback-style shell panel. Mirrors the formatting choices
/// in egui's DOM scrollback adapter at a basic level — header lines,
/// indented entries, type/size/hash for entity views.
///
/// Streaming variants (`Lines` / `Dispatch`) are not yet reachable
/// from the synchronous Tier C verbs we adopt here. They're handled
/// with a placeholder message so the dispatcher is total.
fn render_output(out: &VerbOutput) -> String {
    match out {
        VerbOutput::Path(p) => p.clone(),
        VerbOutput::Message(m) => m.clone(),
        VerbOutput::Listing { sections } => render_listing(sections),
        VerbOutput::Entity(view) => render_entity(view),
        VerbOutput::Tree(view) => render_tree(view),
        VerbOutput::Info(rows) => render_info(rows),
        VerbOutput::Lines(_) | VerbOutput::Dispatch(_) => {
            // Async verbs (connect, exec) are deferred from this
            // adoption slice. If we hit this, an async verb got wired
            // without the streaming UI side.
            "(streaming output not yet supported on the Godot side)".to_string()
        }
    }
}

fn render_listing(sections: &[ListingSection]) -> String {
    let mut out = String::new();
    for (i, section) in sections.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if let Some(header) = &section.header {
            out.push_str(header);
            out.push('\n');
        }
        for entry in &section.entries {
            out.push_str(entry);
            out.push('\n');
        }
    }
    // Drop the trailing newline so the scrollback's own `append + "\n"`
    // doesn't produce a blank line at the end of every listing.
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

fn render_entity(view: &EntityView) -> String {
    format!(
        "{}\n  type: {}\n  size: {} bytes\n\n{}",
        view.path, view.entity_type, view.byte_len, view.body,
    )
}

fn render_tree(view: &TreeView) -> String {
    let mut out = String::new();
    out.push_str(&view.root);
    if let Some(depth) = view.depth_limit {
        out.push_str(&format!(" (depth ≤ {})", depth));
    }
    out.push('\n');
    for entry in &view.entries {
        for _ in 0..entry.depth {
            out.push_str("  ");
        }
        out.push_str(&entry.path);
        out.push('\n');
    }
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

fn render_info(rows: &[InfoRow]) -> String {
    // Right-align labels to the widest label width for readability;
    // rows without a label render as plain values (used by `info` for
    // section separators or trailing free-text lines).
    let label_width = rows
        .iter()
        .filter_map(|r| r.label.as_deref().map(str::len))
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        match &row.label {
            Some(label) => out.push_str(&format!(
                "{:>width$}: {}",
                label,
                row.value,
                width = label_width
            )),
            None => out.push_str(&row.value),
        }
    }
    out
}
