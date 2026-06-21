//! PeerOpFuture — Godot-side handle for an in-flight L1 peer operation.
//!
//! Returned by `EntityPeer::tree_*_async`, `subscribe_l1`, and the
//! extension-config helpers. Emits `completed(result: Variant)` exactly
//! once when the underlying SDK call resolves.
//!
//! GDScript usage:
//!     var fut := peer.tree_get_async(path)
//!     fut.completed.connect(_on_complete, CONNECT_ONE_SHOT)
//!     # ...or...
//!     var result = await fut.completed
//!
//! ## Why polling and not call_deferred
//!
//! Godot's `Object::emit_signal` is main-thread-only. The tokio task that
//! drives the SDK call runs on a worker thread and can't touch the
//! godot-rust runtime. Two viable bridges: `call_deferred` (Godot ticks
//! the call on the main loop next process) or polling from
//! `EntityPeer::_process`. We pick polling because it keeps the failure
//! mode "your future never fires until you have a live `EntityPeer` in
//! the scene tree," which matches the rest of the binding's pattern (the
//! tree_changed signal bridge uses the same `_process` drain). One main-
//! thread tick of latency on resolution, deterministic ordering with
//! other peer signals — and no thread-affinity surprises if a caller
//! awaits the future from a tokio context they shouldn't be in.
//!
//! Pending futures are owned by `EntityPeer` (Vec<Gd<PeerOpFuture>>) so
//! they stay alive after the GDScript caller drops its reference and
//! before the signal fires. After emission, `EntityPeer` drops its entry
//! and the future deallocates on the next refcount tick.

use std::sync::{Arc, Mutex};

use godot::prelude::*;

use entity_entity::Entity;
use entity_hash::Hash;

use crate::entity_resource::EntityData;
use crate::entity_subscription::EntitySubscription;

/// Raw, Send-safe result of an L1 op — produced on the tokio worker,
/// consumed on the Godot main thread (where Variants are valid).
///
/// One variant per op shape. Add a new variant when adding a new
/// async method to `EntityPeer`. Keep this thin and Send — no
/// `Gd<...>`, no Variants, no godot-runtime references.
pub(crate) enum OpResultRaw {
    /// `tree_get_async` — `Some(entity)` on hit, `None` on miss.
    Entity(Option<Entity>),
    /// `tree_put_async`, `enable_*`, `disable_*` — content hash on success.
    Hash(Hash),
    /// `tree_list_async` — paths under the prefix.
    PathList(Vec<String>),
    /// `tree_has_async`, `tree_remove_async`.
    Bool(bool),
    /// `subscribe_l1` — handed the live subscription to the main thread
    /// so it can be wrapped in an `EntitySubscription` (which contains a
    /// queue we filled from the L1 callback on the tokio side).
    Subscription(SubscriptionPayload),
    /// `query_async` — full QueryResults shape (matches + pagination
    /// metadata).
    QueryResults(entity_sdk::QueryResults),
    /// `count_async`. Reserved for future numeric ops.
    Int(i64),
    /// `discover_handlers` — typed handler info per peer entry.
    HandlerList(Vec<entity_sdk::HandlerInfo>),
    /// `discover_types` — typed type info (with field shapes) per peer entry.
    TypeList(Vec<entity_sdk::TypeInfo>),
    /// `history_query_async` — typed history query result (path, head,
    /// transitions, has_more). Decoded by the SDK from the
    /// `system/history:query` envelope.
    HistoryQuery(entity_sdk::HistoryQueryResult),
    /// `history_rollback_async`. The hash carried back is the
    /// `target_hash` the caller passed in — the rollback handler returns
    /// the restored hash but the SDK helper drops it; we round-trip the
    /// caller's input on success so GDScript gets the same shape as a
    /// future rollback handler that did surface the field.
    HistoryRollback(Hash),
    /// `revision_log_async` — list of version entries under a prefix
    /// (decoded from the envelope's `versions[]` + `included` map).
    /// Per `PROPOSAL-STRUCTURAL-VERSION-ENTRIES` each entry carries only
    /// `{hash, root, parents}` — author / timestamp / message do not
    /// exist on revision entries.
    RevisionLog {
        prefix: String,
        versions: Vec<RevisionVersionInfo>,
        has_more: bool,
    },
    /// `revision_checkout_async` — accepted checkout result. We surface
    /// the structural fields the handler returns; cascade_warnings and
    /// uncommitted_changes ride along for callers that care.
    RevisionCheckout {
        head: Hash,
        target_version: Hash,
        branch: Option<String>,
        cascade_warnings: Vec<String>,
        uncommitted_changes: bool,
    },
    /// `connect_to_async` — outbound peer connection result.
    /// Carries the remote peer_id on success; the inner `String` is the
    /// human-readable error on failure (status is implicit in `Ok` vs
    /// the existing `Err` variant — kept here for the Dictionary shape
    /// the request asked for).
    ConnectTo(Result<String, String>),
    /// `compute_eval_async` — typed compute result + raw entity for
    /// CBOR-fidelity access. Surface shape per `compute_ops.rs`.
    ComputeEval(entity_sdk::compute::ComputeEvalResult),
    /// `compute_install_async` — subgraph_path + result_path the
    /// handler chose for the installed reactive subgraph.
    ComputeInstall(entity_sdk::compute::ComputeInstallResult),
    /// `bootstrap_identity_async` and `restore_identity_bundle_async`
    /// both end in this shape — peer's identity stack is now live.
    Bootstrap(entity_sdk::identity_bootstrap::BootstrapResult),
    /// `inbox_list_async` — pending inbox entries (path + hash).
    InboxList(Vec<entity_store::LocationEntry>),
    /// `inbox_send_async` — storage path of the delivered message
    /// (`{target_path}/{request_id}`).
    InboxSend(String),
    /// `list_entities_async` — (path, entity) pairs under a prefix.
    PathEntityList(Vec<(String, Entity)>),
    /// Generic handler dispatch result for ops whose result is the
    /// raw handler envelope (continuation resume/advance, etc.).
    /// Surfaces as Dictionary `{status: int, result: EntityData}`.
    HandlerOk(entity_handler::HandlerResult),
    /// `clock_now_async` — typed clock state per the peer's mode.
    ClockState(entity_sdk::ClockState),
    /// `clock_compare_async` — ordering result (-1/0/1/concurrent → int).
    ClockOrder(entity_sdk::ClockOrder),
    /// `revision_commit_async` — new version + root + parent.
    RevisionCommit(entity_sdk::revision::CommitResult),
    /// `revision_status_async` — current HEAD + conflict count.
    RevisionStatusResult(entity_sdk::revision::RevisionStatus),
    /// `revision_config_delete_async` — ConfigResult shape.
    RevisionConfig(entity_sdk::revision::ConfigResult),
    /// `revision_merge_config_delete_async` — MergeConfigResult shape.
    RevisionMergeConfig(entity_sdk::revision::MergeConfigResult),
    /// Any SDK error path — reported as a Godot error log + Nil result.
    /// The string is the human-readable error from `SdkError::to_string()`.
    Err(String),
}

/// Structural-only revision version entry per
/// `PROPOSAL-STRUCTURAL-VERSION-ENTRIES`. Surfaced as a Dictionary on
/// the Godot side; carried Send-safe here.
pub(crate) struct RevisionVersionInfo {
    pub hash: Hash,
    pub root: Option<Hash>,
    pub parents: Vec<Hash>,
}

/// Side-table for the L1 subscribe result. The handle keeps the
/// subscription alive; the queue is the same one the L1 callback writes
/// into. `EntityPeer::_process` builds an `EntitySubscription` from this
/// pair on the main thread.
pub(crate) struct SubscriptionPayload {
    pub handle: entity_sdk::subscription::L1SubscriptionHandle,
    pub queue: Arc<Mutex<std::collections::VecDeque<(String, Vec<u8>)>>>,
}

/// A handle for one in-flight async op. Emits `completed(result)` once
/// on success or error.
///
/// ## Safe await pattern (audit AUDIT-INGEST-HANG)
///
/// `completed` is a one-shot signal emitted via `call_deferred`. Once
/// `_process` has polled this future and queued the deferred emit, any
/// connect-or-await registered AFTER the deferred emit fires will miss
/// the signal — there is no replay. GDScript callers that await many
/// futures sequentially (e.g. a sliding-window barrier draining N
/// in-flight puts) hit this race every time tokio resolves a put
/// during the GDScript code between awaits.
///
/// Fix shape: the completion Variant is **cached on the future** before
/// the deferred emit. `result()` returns it; `is_done()` reports whether
/// it is set. The canonical await pattern is now:
///
/// ```gdscript
/// # Direct (every site, manual):
/// var v: Variant
/// if fut.is_done():
///     v = fut.result()
/// else:
///     v = await fut.completed
///
/// # Via helper (recommended — see core/peer_op_helpers.gd):
/// var v: Variant = await PeerOpHelpers.await_result(fut)
/// ```
#[derive(GodotClass)]
#[class(no_init, base=RefCounted)]
pub struct PeerOpFuture {
    base: Base<RefCounted>,
    /// Slot the tokio task fills; the main thread drains it in
    /// `try_complete`. `None` means the task hasn't finished yet.
    slot: Arc<Mutex<Option<OpResultRaw>>>,
    /// Set to `true` after `completed` fires, so `EntityPeer` can drop
    /// the entry from its pending list and a stray re-poll is a no-op.
    emitted: bool,
    /// Latched result Variant — set in `try_complete` before the
    /// deferred emit. Exposed via the `result()` accessor so callers
    /// who arrive after the signal has fired can still retrieve the
    /// value. Without this, the signal-emit race in §H3 of the audit
    /// causes silent hangs (the await registers a one-shot listener
    /// for a signal that already fired). Cloned from the variant we
    /// pass into `call_deferred` — Variant clone is cheap (ref-count).
    cached_result: Option<Variant>,
}

impl PeerOpFuture {
    /// Construct a fresh pending future. The returned `Arc` is what the
    /// tokio task fills.
    pub(crate) fn new_pending() -> (Gd<Self>, Arc<Mutex<Option<OpResultRaw>>>) {
        let slot = Arc::new(Mutex::new(None));
        let slot_for_caller = slot.clone();
        let gd = Gd::from_init_fn(|base| Self {
            base,
            slot,
            emitted: false,
            cached_result: None,
        });
        (gd, slot_for_caller)
    }

    /// Called from `EntityPeer::_process`. Drains the slot if the task
    /// has finished, converts the raw result into a Godot Variant on the
    /// main thread, queues the signal emit for the next idle frame.
    /// Returns `true` once the future has emitted (or was emitted on a
    /// previous tick) — the caller drops it from its pending list when
    /// this returns `true`.
    ///
    /// ── Why the emit is deferred (godot-workbench Wave 2.1) ──
    /// `try_complete` runs inside `EntityPeer::process`, which holds a
    /// `&mut self` borrow on `EntityPeer` for the duration. Godot signal
    /// callbacks fire synchronously by default — and `await fut.completed`
    /// in GDScript registers a synchronous one-shot. The natural pattern
    /// (`var r = await peer.tree_put_async(...).completed; peer.tree_get(...)`)
    /// would resume the coroutine inside our own `_process`, immediately
    /// call back into `EntityPeer`, and panic with
    /// "Gd<EntityPeer>::bind() failed, already bound."
    ///
    /// Deferring the emit via `call_deferred` queues it for the next idle
    /// frame — by then `_process` has returned, `&mut self` is released,
    /// and the resumed coroutine can safely re-enter `EntityPeer`. Costs
    /// one extra main-thread tick of latency; preserves the
    /// `await`-and-then-call-the-peer pattern documented in the request.
    pub(crate) fn try_complete(&mut self) -> bool {
        if self.emitted {
            return true;
        }
        let raw = match self.slot.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => return false,
        };
        let Some(raw) = raw else {
            return false;
        };
        let variant = raw_to_variant(raw);
        self.emitted = true;
        // CACHE BEFORE EMIT — see "Safe await pattern" doc above. The
        // emit is `call_deferred`; any await registered after the emit
        // fires would miss the signal. `result()` reads this cache so
        // late-arriving consumers still get the value.
        self.cached_result = Some(variant.clone());
        self.base_mut().call_deferred(
            "emit_signal",
            &["completed".to_variant(), variant],
        );
        true
    }

    /// Force-complete this future with a `Nil` result and a
    /// `godot_error!` log carrying `msg`. Used by `EntityPeer::stop`
    /// to unwind any in-flight coroutines so they don't hang on a
    /// signal that will never fire (the runtime is about to be torn
    /// down). Idempotent if the future has already emitted.
    ///
    /// The emit is deferred (same reasoning as `try_complete`): a
    /// GDScript coroutine resuming from `await fut.completed`
    /// must not re-enter `EntityPeer` while the borrow that called
    /// `stop` is still held.
    pub(crate) fn fail_with(&mut self, msg: &str) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        self.cached_result = Some(Variant::nil());
        godot_error!("PeerOpFuture failed: {}", msg);
        self.base_mut().call_deferred(
            "emit_signal",
            &["completed".to_variant(), Variant::nil()],
        );
    }
}

#[godot_api]
impl PeerOpFuture {
    /// Fires once with the operation's result. Result shape depends on
    /// the op — see each `EntityPeer::*_async` method's docs.
    #[signal]
    fn completed(result: Variant);

    /// True once `completed` has fired. For `await` callers this is
    /// uninteresting; for poll-style callers it lets them check without
    /// connecting a one-shot.
    #[func]
    fn is_done(&self) -> bool {
        self.emitted
    }

    /// Returns the cached completion result, or `null` if the future
    /// has not yet emitted. Pair with `is_done()` to retrieve a result
    /// that may have already been signaled before the caller could
    /// register a listener. See the type-level "Safe await pattern"
    /// doc and `core/peer_op_helpers.gd::await_result()` in the godot-
    /// workbench app for the canonical use site.
    #[func]
    fn result(&self) -> Variant {
        match &self.cached_result {
            Some(v) => v.clone(),
            None => Variant::nil(),
        }
    }
}

/// Convert the raw result into the Variant shape GDScript will see.
///
/// Shape per op:
/// - `Entity`         → `EntityData` (Object) or `null`
/// - `Hash`           → `PackedByteArray` (33 bytes)
/// - `PathList`       → `PackedStringArray`
/// - `Bool`           → `bool`
/// - `Subscription`   → `EntitySubscription` (Object)
/// - `QueryResults`   → `Dictionary { matches, has_more, total, cursor }`
/// - `Int`            → `int` (i64)
/// - `HandlerList`    → `Array[Dictionary { pattern, name, operations }]`
/// - `TypeList`       → `Array[Dictionary { type_path, fields[] }]`
/// - `Err`            → `null` (and `godot_error!` log; no exception)
fn raw_to_variant(raw: OpResultRaw) -> Variant {
    match raw {
        OpResultRaw::Entity(Some(e)) => EntityData::from_entity(&e).to_variant(),
        OpResultRaw::Entity(None) => Variant::nil(),
        OpResultRaw::Hash(h) => {
            let bytes = h.to_bytes();
            let mut pba = PackedByteArray::new();
            pba.extend(bytes.iter().copied());
            pba.to_variant()
        }
        OpResultRaw::PathList(paths) => {
            let mut arr = PackedStringArray::new();
            for p in paths {
                arr.push(&GString::from(p.as_str()));
            }
            arr.to_variant()
        }
        OpResultRaw::Bool(b) => b.to_variant(),
        OpResultRaw::Subscription(payload) => {
            EntitySubscription::new_gd_with_l1(payload.queue, payload.handle).to_variant()
        }
        OpResultRaw::QueryResults(qr) => query_results_to_variant(qr),
        OpResultRaw::Int(n) => n.to_variant(),
        OpResultRaw::HandlerList(list) => handler_list_to_variant(list),
        OpResultRaw::TypeList(list) => type_list_to_variant(list),
        OpResultRaw::HistoryQuery(r) => history_query_to_variant(r),
        OpResultRaw::HistoryRollback(h) => history_rollback_ok_to_variant(h),
        OpResultRaw::RevisionLog { prefix, versions, has_more } => {
            revision_log_to_variant(prefix, versions, has_more)
        }
        OpResultRaw::RevisionCheckout {
            head,
            target_version,
            branch,
            cascade_warnings,
            uncommitted_changes,
        } => revision_checkout_ok_to_variant(
            head,
            target_version,
            branch,
            cascade_warnings,
            uncommitted_changes,
        ),
        OpResultRaw::ConnectTo(r) => connect_to_to_variant(r),
        OpResultRaw::ComputeEval(r) => crate::compute_ops::compute_eval_result_to_variant(r),
        OpResultRaw::ComputeInstall(r) => crate::compute_ops::compute_install_result_to_variant(r),
        OpResultRaw::Bootstrap(r) => crate::bootstrap_ops::bootstrap_result_to_variant(r),
        OpResultRaw::InboxList(entries) => inbox_list_to_variant(entries),
        OpResultRaw::InboxSend(path) => GString::from(path.as_str()).to_variant(),
        OpResultRaw::PathEntityList(pairs) => path_entity_list_to_variant(pairs),
        OpResultRaw::HandlerOk(r) => handler_result_to_variant(r),
        OpResultRaw::ClockState(s) => clock_state_to_variant(s),
        OpResultRaw::ClockOrder(o) => clock_order_to_variant(o),
        OpResultRaw::RevisionCommit(r) => revision_commit_to_variant(r),
        OpResultRaw::RevisionStatusResult(r) => revision_status_to_variant(r),
        OpResultRaw::RevisionConfig(r) => revision_config_to_variant(r),
        OpResultRaw::RevisionMergeConfig(r) => revision_merge_config_to_variant(r),
        OpResultRaw::Err(msg) => {
            godot_error!("EntityPeer async op failed: {}", msg);
            Variant::nil()
        }
    }
}

fn query_results_to_variant(qr: entity_sdk::QueryResults) -> Variant {
    let mut out = VarDictionary::new();
    let mut matches = VarArray::new();
    for m in qr.matches {
        let mut md = VarDictionary::new();
        md.set(GString::from("path"), GString::from(m.path.as_str()));
        let mut hash_pba = PackedByteArray::new();
        hash_pba.extend(m.content_hash.to_bytes().iter().copied());
        md.set(GString::from("content_hash"), hash_pba);
        md.set(GString::from("entity_type"), GString::from(m.entity_type.as_str()));
        let entity_var = match m.entity {
            Some(ref e) => EntityData::from_entity(e).to_variant(),
            None => Variant::nil(),
        };
        md.set(GString::from("entity"), entity_var);
        matches.push(&md.to_variant());
    }
    out.set(GString::from("matches"), matches);
    out.set(GString::from("has_more"), qr.has_more);
    // `total` is u64 on the SDK side; saturate to i64::MAX rather than wrap
    // (Godot ints are i64; in practice query totals never approach this).
    let total_i64 = i64::try_from(qr.total).unwrap_or(i64::MAX);
    out.set(GString::from("total"), total_i64);
    out.set(
        GString::from("cursor"),
        GString::from(qr.cursor.unwrap_or_default().as_str()),
    );
    out.to_variant()
}

fn handler_list_to_variant(list: Vec<entity_sdk::HandlerInfo>) -> Variant {
    let mut out = VarArray::new();
    for h in list {
        let mut d = VarDictionary::new();
        d.set(GString::from("pattern"), GString::from(h.pattern.as_str()));
        d.set(GString::from("name"), GString::from(h.name.as_str()));
        let mut ops = PackedStringArray::new();
        for op in h.operations {
            ops.push(&GString::from(op.as_str()));
        }
        d.set(GString::from("operations"), ops);
        out.push(&d.to_variant());
    }
    out.to_variant()
}

fn hash_to_pba(h: &Hash) -> PackedByteArray {
    let mut pba = PackedByteArray::new();
    pba.extend(h.to_bytes().iter().copied());
    pba
}

fn history_query_to_variant(r: entity_sdk::HistoryQueryResult) -> Variant {
    let mut out = VarDictionary::new();
    out.set(GString::from("path"), GString::from(r.path.as_str()));
    let head_var = match r.head {
        Some(ref h) => hash_to_pba(h).to_variant(),
        None => Variant::nil(),
    };
    out.set(GString::from("head"), head_var);
    let mut transitions = VarArray::new();
    for t in r.transitions {
        let mut td = VarDictionary::new();
        td.set(GString::from("event"), GString::from(t.event.as_str()));
        let hash_var = match t.hash {
            Some(ref h) => hash_to_pba(h).to_variant(),
            None => Variant::nil(),
        };
        td.set(GString::from("hash"), hash_var);
        let prev_var = match t.previous_hash {
            Some(ref h) => hash_to_pba(h).to_variant(),
            None => Variant::nil(),
        };
        td.set(GString::from("previous_hash"), prev_var);
        td.set(
            GString::from("timestamp"),
            i64::try_from(t.timestamp).unwrap_or(i64::MAX),
        );
        transitions.push(&td.to_variant());
    }
    out.set(GString::from("transitions"), transitions);
    out.set(GString::from("has_more"), r.has_more);
    out.to_variant()
}

fn history_rollback_ok_to_variant(restored: Hash) -> Variant {
    let mut out = VarDictionary::new();
    out.set(GString::from("status"), GString::from("ok"));
    out.set(GString::from("rolled_back_to"), hash_to_pba(&restored));
    out.to_variant()
}

fn revision_log_to_variant(
    prefix: String,
    versions: Vec<RevisionVersionInfo>,
    has_more: bool,
) -> Variant {
    let mut out = VarDictionary::new();
    out.set(GString::from("prefix"), GString::from(prefix.as_str()));
    let mut commits = VarArray::new();
    for v in versions {
        let mut d = VarDictionary::new();
        d.set(GString::from("hash"), hash_to_pba(&v.hash));
        let root_var = match v.root {
            Some(ref h) => hash_to_pba(h).to_variant(),
            None => Variant::nil(),
        };
        d.set(GString::from("root"), root_var);
        let mut parents = VarArray::new();
        for p in v.parents {
            parents.push(&hash_to_pba(&p).to_variant());
        }
        d.set(GString::from("parents"), parents);
        commits.push(&d.to_variant());
    }
    out.set(GString::from("commits"), commits);
    out.set(GString::from("has_more"), has_more);
    out.to_variant()
}

fn revision_checkout_ok_to_variant(
    head: Hash,
    target_version: Hash,
    branch: Option<String>,
    cascade_warnings: Vec<String>,
    uncommitted_changes: bool,
) -> Variant {
    let mut out = VarDictionary::new();
    out.set(GString::from("status"), GString::from("ok"));
    out.set(GString::from("checked_out"), hash_to_pba(&target_version));
    out.set(GString::from("head"), hash_to_pba(&head));
    let branch_var = match branch {
        Some(ref s) => GString::from(s.as_str()).to_variant(),
        None => Variant::nil(),
    };
    out.set(GString::from("branch"), branch_var);
    let mut warns = PackedStringArray::new();
    for w in cascade_warnings {
        warns.push(&GString::from(w.as_str()));
    }
    out.set(GString::from("cascade_warnings"), warns);
    out.set(GString::from("uncommitted_changes"), uncommitted_changes);
    out.to_variant()
}

fn connect_to_to_variant(r: Result<String, String>) -> Variant {
    let mut out = VarDictionary::new();
    match r {
        Ok(remote) => {
            out.set(GString::from("status"), GString::from("ok"));
            out.set(GString::from("remote_peer_id"), GString::from(remote.as_str()));
        }
        Err(e) => {
            out.set(GString::from("status"), GString::from("error"));
            out.set(GString::from("error"), GString::from(e.as_str()));
        }
    }
    out.to_variant()
}

/// Surface a `ClockState` as a Dictionary tagged by `mode`:
///   { mode: "wall"|"logical"|"vector"|"hlc",
///     timestamp_ms?: int, logical?: int,
///     vector?: Dictionary[String → int],
///     hlc?: { physical, logical, peer: PBA } }
fn clock_state_to_variant(s: entity_sdk::ClockState) -> Variant {
    let mut out = VarDictionary::new();
    out.set(GString::from("mode"), GString::from(s.mode.as_str()));
    if let Some(ts) = s.timestamp_ms {
        out.set(GString::from("timestamp_ms"), ts as i64);
    }
    if let Some(l) = s.logical {
        out.set(GString::from("logical"), l as i64);
    }
    if let Some(vec) = s.vector {
        let mut v = VarDictionary::new();
        for (peer, count) in vec {
            v.set(GString::from(peer.as_str()), count as i64);
        }
        out.set(GString::from("vector"), v);
    }
    if let Some(h) = s.hlc {
        let mut d = VarDictionary::new();
        d.set(GString::from("physical"), h.physical as i64);
        d.set(GString::from("logical"), h.logical as i64);
        d.set(GString::from("peer"), hash_to_pba(&h.peer));
        out.set(GString::from("hlc"), d);
    }
    out.to_variant()
}

/// `ClockOrder` → int: -1 (Before), 0 (Equal), 1 (After), 2 (Concurrent).
fn clock_order_to_variant(o: entity_sdk::ClockOrder) -> Variant {
    let n: i64 = match o {
        entity_sdk::ClockOrder::Before => -1,
        entity_sdk::ClockOrder::Equal => 0,
        entity_sdk::ClockOrder::After => 1,
        entity_sdk::ClockOrder::Concurrent => 2,
    };
    n.to_variant()
}

fn revision_commit_to_variant(r: entity_sdk::revision::CommitResult) -> Variant {
    let mut out = VarDictionary::new();
    out.set(GString::from("version"), hash_to_pba(&r.version));
    out.set(GString::from("root"), hash_to_pba(&r.root));
    match r.parent {
        Some(p) => out.set(GString::from("parent"), hash_to_pba(&p)),
        None => out.set(GString::from("parent"), Variant::nil()),
    }
    out.to_variant()
}

fn revision_status_to_variant(r: entity_sdk::revision::RevisionStatus) -> Variant {
    let mut out = VarDictionary::new();
    match r.head {
        Some(h) => out.set(GString::from("head"), hash_to_pba(&h)),
        None => out.set(GString::from("head"), Variant::nil()),
    }
    out.set(GString::from("conflicts"), r.conflicts as i64);
    out.to_variant()
}

fn revision_config_to_variant(r: entity_sdk::revision::ConfigResult) -> Variant {
    let mut out = VarDictionary::new();
    out.set(GString::from("config_path"), GString::from(r.config_path.as_str()));
    match r.config_hash {
        Some(h) => out.set(GString::from("config_hash"), hash_to_pba(&h)),
        None => out.set(GString::from("config_hash"), Variant::nil()),
    }
    match r.previous_hash {
        Some(h) => out.set(GString::from("previous_hash"), hash_to_pba(&h)),
        None => out.set(GString::from("previous_hash"), Variant::nil()),
    }
    match r.tracking_config_path {
        Some(p) => out.set(GString::from("tracking_config_path"), GString::from(p.as_str())),
        None => out.set(GString::from("tracking_config_path"), Variant::nil()),
    }
    match r.tracking_config_action {
        Some(a) => out.set(GString::from("tracking_config_action"), GString::from(a.as_str())),
        None => out.set(GString::from("tracking_config_action"), Variant::nil()),
    }
    out.to_variant()
}

fn revision_merge_config_to_variant(r: entity_sdk::revision::MergeConfigResult) -> Variant {
    let mut out = VarDictionary::new();
    out.set(GString::from("path"), GString::from(r.path.as_str()));
    match r.hash {
        Some(h) => out.set(GString::from("hash"), hash_to_pba(&h)),
        None => out.set(GString::from("hash"), Variant::nil()),
    }
    out.set(GString::from("status"), GString::from(r.status.as_str()));
    out.to_variant()
}

fn handler_result_to_variant(r: entity_handler::HandlerResult) -> Variant {
    let mut out = VarDictionary::new();
    out.set(GString::from("status"), r.status as i64);
    out.set(
        GString::from("result"),
        EntityData::from_entity(&r.result),
    );
    out.to_variant()
}

fn inbox_list_to_variant(entries: Vec<entity_store::LocationEntry>) -> Variant {
    let mut out = VarArray::new();
    for e in entries {
        let mut d = VarDictionary::new();
        d.set(GString::from("path"), GString::from(e.path.as_str()));
        d.set(GString::from("hash"), hash_to_pba(&e.hash));
        out.push(&d.to_variant());
    }
    out.to_variant()
}

fn path_entity_list_to_variant(pairs: Vec<(String, Entity)>) -> Variant {
    let mut out = VarArray::new();
    for (path, entity) in pairs {
        let mut d = VarDictionary::new();
        d.set(GString::from("path"), GString::from(path.as_str()));
        d.set(GString::from("entity"), EntityData::from_entity(&entity));
        out.push(&d.to_variant());
    }
    out.to_variant()
}

fn type_list_to_variant(list: Vec<entity_sdk::TypeInfo>) -> Variant {
    let mut out = VarArray::new();
    for t in list {
        let mut d = VarDictionary::new();
        d.set(GString::from("type_path"), GString::from(t.type_path.as_str()));
        let mut fields = VarArray::new();
        for f in t.fields {
            let mut fd = VarDictionary::new();
            fd.set(GString::from("name"), GString::from(f.name.as_str()));
            fd.set(GString::from("type_ref"), GString::from(f.type_ref.as_str()));
            fd.set(GString::from("optional"), f.optional);
            fields.push(&fd.to_variant());
        }
        d.set(GString::from("fields"), fields);
        out.push(&d.to_variant());
    }
    out.to_variant()
}
