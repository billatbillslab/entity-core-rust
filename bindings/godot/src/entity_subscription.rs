//! EntitySubscription — handle for a path-filtered tree-change subscription.
//!
//! Returned by `EntityPeer::watch(prefix)` (L0 store-watch) and indirectly
//! by `EntityPeer::subscribe_l1(prefix)` (L1 dispatched via
//! `system/subscription`). Both flavors push events into a shared queue
//! that GDScript drains via `poll()` on its own cadence (typically per-
//! frame in `_process`). Drop the EntitySubscription (release the GDScript
//! reference) to cancel.
//!
//! L0 vs L1 is opaque at the GDScript API surface — same poll/event shape
//! either way. The internal handle's `Drop` impl runs the appropriate
//! cancellation (`SubscriptionHandle::drop` → atomic cancel flag for L0;
//! `L1SubscriptionHandle::drop` → close registered handler + dispatch
//! `unsubscribe` for L1).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use godot::prelude::*;

use entity_sdk::sdk::SubscriptionHandle;
use entity_sdk::subscription::L1SubscriptionHandle;

/// Internal: which kind of subscription handle this wraps. We hold the
/// handle only for its `Drop` side effect — never invoked beyond that —
/// so an enum is the cleanest way to keep both flavors alive without a
/// `Box<dyn Any>` dance.
///
/// `dead_code` is silenced because the inner handles are read by the
/// compiler-generated `Drop` glue, not by any pattern match.
#[allow(dead_code)]
enum SubKind {
    L0(SubscriptionHandle),
    L1(L1SubscriptionHandle),
}

/// Pull-based subscription handle.
///
/// Methods:
/// - `poll() -> Array[Dictionary]` — drain pending events since the last call.
///   Each entry is `{ "path": String, "hash": PackedByteArray }`.
/// - `has_pending() -> bool` — true if there are events to drain.
/// - `pending_count() -> int` — number of events currently buffered.
#[derive(GodotClass)]
#[class(no_init, base=RefCounted)]
pub struct EntitySubscription {
    base: Base<RefCounted>,
    queue: Arc<Mutex<VecDeque<(String, Vec<u8>)>>>,
    /// Held to keep the underlying subscription alive. Drop = cancel.
    /// The `#[allow]` is because the field is read only by `Drop`.
    #[allow(dead_code)]
    handle: SubKind,
}

impl EntitySubscription {
    /// L0 constructor used by `EntityPeer::watch`.
    pub fn new_gd_with_handle(
        queue: Arc<Mutex<VecDeque<(String, Vec<u8>)>>>,
        handle: SubscriptionHandle,
    ) -> Gd<Self> {
        Gd::from_init_fn(|base| Self {
            base,
            queue,
            handle: SubKind::L0(handle),
        })
    }

    /// L1 constructor used by `EntityPeer::subscribe_l1` (through the
    /// `PeerOpFuture` completion path).
    pub fn new_gd_with_l1(
        queue: Arc<Mutex<VecDeque<(String, Vec<u8>)>>>,
        handle: L1SubscriptionHandle,
    ) -> Gd<Self> {
        Gd::from_init_fn(|base| Self {
            base,
            queue,
            handle: SubKind::L1(handle),
        })
    }
}

#[godot_api]
impl EntitySubscription {
    /// Drain events that have arrived since the last poll. Empty array if none.
    #[func]
    fn poll(&self) -> Array<VarDictionary> {
        let Ok(mut q) = self.queue.lock() else {
            return Array::new();
        };
        let mut result: Array<VarDictionary> = Array::new();
        while let Some((path, hash)) = q.pop_front() {
            let mut d = VarDictionary::new();
            let _ = d.insert("path", GString::from(path.as_str()).to_variant());
            let mut h = PackedByteArray::new();
            h.extend(hash.into_iter());
            let _ = d.insert("hash", h.to_variant());
            result.push(&d);
        }
        result
    }

    /// True if events are buffered.
    #[func]
    fn has_pending(&self) -> bool {
        self.queue.lock().map(|q| !q.is_empty()).unwrap_or(false)
    }

    /// Number of buffered events.
    #[func]
    fn pending_count(&self) -> i64 {
        self.queue.lock().map(|q| q.len() as i64).unwrap_or(0)
    }
}
