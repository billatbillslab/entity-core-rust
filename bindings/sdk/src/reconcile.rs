//! `ReconcileSinceLastSeen` — state catch-up after silent saturation
//! drops or peer-restart downtime.
//!
//! Wraps the documented `revision:fetch-diff + tree:merge` chain from
//! `GUIDE-CONTINUATIONS-WORKBENCH §5` + `EXTENSION-REVISION §4.4.19`
//! as a single SDK call.
//!
//! ## Use cases
//!
//! 1. After a saturation burst: a subscription dropped some
//!    notifications; the caller wants to make sure local tree state
//!    matches the publisher.
//! 2. After a peer restart: the caller called
//!    `RestorePriorSubscriptions` but still missed writes that
//!    happened during downtime.
//! 3. Periodic reconciliation: belt-and-suspenders for long-lived
//!    collaborative workspaces.
//!
//! ## Cross-peer fetch-diff (D4 caveat)
//!
//! This wrapper dispatches `system/revision:fetch-diff` against the
//! remote peer's URI (`entity://{remote}/system/revision`) — the
//! intentional cross-peer use case. The Rust handler in
//! `extensions/revision/src/lib.rs:2484` currently enforces
//! `PROPOSAL-CONVERGENT-MIRRORING §2.3 D4` strictly and rejects all
//! cross-peer fetch-diff with `400 invalid_dispatch`. Until the D4
//! enforcement relaxes to permit explicit cross-peer use (logged in
//! `docs/SPEC-AMBIGUITIES.md`), this wrapper will return that 400 to
//! the caller when targeting a Rust peer. **Go SDK parity is the
//! convergence target** (Go has heavily tested two-peer reconcile);
//! the wire shape and SDK surface match
//! `workbench-go/entitysdk/reconcile.go`.

use crate::sdk::{PeerContext, SdkError};
use entity_capability::ResourceTarget;
use entity_entity::Entity;
use entity_handler::ExecuteOptions;
use entity_hash::Hash;

/// Summary of a reconciliation pass.
#[derive(Debug, Clone)]
pub struct ReconcileResult {
    /// The prefix that was reconciled (echoes the caller's input).
    pub prefix: String,
    /// The remote peer-id the diff was fetched from.
    pub remote_peer_id: String,
    /// The base hash supplied to fetch-diff. `None` indicates a full-
    /// closure pull (equivalent to bootstrap).
    pub base_hash: Option<Hash>,
    /// Count of entities pulled across the wire (trie nodes + leaves
    /// combined) — a rough measure of "how much state changed since
    /// the base." Zero either means the base was already up-to-date
    /// or the wrapper couldn't decode the envelope for metrics.
    pub entities_ingested: usize,
}

impl PeerContext {
    /// Pull the delta between `last_seen` and `remote_peer_id`'s
    /// current HEAD for `prefix`, applying the result via
    /// `tree:merge` with `strategy: "source-wins"`.
    ///
    /// **Pre-conditions:**
    /// - Local peer has an open connection to `remote_peer_id`
    ///   (use `PeerContext::connect` or the higher-level transport
    ///   setup beforehand).
    /// - Both peers agree on `prefix`.
    ///
    /// `last_seen = None` reconciles against the full current closure
    /// — equivalent to a bootstrap pull. Pass `Some(hash)` for an
    /// incremental sync from the last revision the caller observed.
    ///
    /// Matches Go SDK's `AppPeer.ReconcileSinceLastSeen`
    /// (`workbench-go/entitysdk/reconcile.go:62`). Closes Stage 5
    /// findings F3 (no implicit catch-up after saturation drops) and
    /// F7 (missed writes recoverable but only via explicit pull)
    /// from the consumer-side.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn reconcile_since_last_seen(
        &self,
        remote_peer_id: impl Into<String>,
        prefix: impl Into<String>,
        last_seen: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, SdkError>> + Send + 'static
    {
        let remote_peer_id = remote_peer_id.into();
        let prefix = prefix.into();

        // Synchronous validation — return the future before either
        // execute call is built when inputs are malformed.
        let validation_err = pre_validate(&remote_peer_id, &prefix);

        // Build both futures up-front so the wrapper doesn't have to
        // hold &self across awaits. self.execute() takes &self but
        // returns a 'static future (capturing shared+owner_cap by
        // clone), so this is just two independent dispatch futures.
        // We can't build the merge future yet — it needs the
        // envelope from step 1 — so we capture the shared state via
        // a fresh self.execute() call inside the async block below.
        let fetch_diff_params = build_fetch_diff_params(&prefix, last_seen);
        let fetch_diff_uri = format!("entity://{}/system/revision", remote_peer_id);
        let fetch_fut = self.execute(
            fetch_diff_uri,
            "fetch-diff",
            fetch_diff_params,
            ExecuteOptions::default(),
        );

        // We need a second execute() for tree:merge, but Rust's
        // borrow-checker won't let us hold &self across the await.
        // Solution: clone the shared state we need NOW, then build
        // the merge execute manually inside the async block. The
        // shared+owner_cap clone matches what PeerContext::execute
        // does internally — see sdk.rs:1828+.
        let shared = self.shared.clone();
        let owner_cap = self.owner_self_cap.clone();

        async move {
            if let Some(e) = validation_err {
                return Err(e);
            }
            let fetch_result = fetch_fut.await?;
            if let Some(err) = SdkError::from_handler_result(
                &fetch_result,
                "reconcile: revision:fetch-diff",
            ) {
                return Err(err);
            }
            let envelope = fetch_result.result;
            let entities_ingested = count_envelope_included(&envelope);

            // Step 2: tree:merge locally.
            let merge_params = build_tree_merge_params(&envelope, &prefix, "source-wins");
            let local_identity = shared.identity_hash;
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared,
                Some(local_identity),
                std::collections::HashMap::new(),
                None,
                Some(owner_cap),
            );
            let merge_result = execute_fn(
                "system/tree".into(),
                "merge".into(),
                merge_params,
                ExecuteOptions::default(),
            )
            .await
            .map_err(|e| SdkError::HandlerError(e.to_string()))?;
            if let Some(err) = SdkError::from_handler_result(&merge_result, "reconcile: tree:merge")
            {
                return Err(err);
            }

            Ok(ReconcileResult {
                prefix,
                remote_peer_id,
                base_hash: last_seen,
                entities_ingested,
            })
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn reconcile_since_last_seen(
        &self,
        remote_peer_id: impl Into<String>,
        prefix: impl Into<String>,
        last_seen: Option<Hash>,
    ) -> impl std::future::Future<Output = Result<ReconcileResult, SdkError>> + 'static {
        let remote_peer_id = remote_peer_id.into();
        let prefix = prefix.into();
        let validation_err = pre_validate(&remote_peer_id, &prefix);

        let fetch_diff_params = build_fetch_diff_params(&prefix, last_seen);
        let fetch_diff_uri = format!("entity://{}/system/revision", remote_peer_id);
        let fetch_fut = self.execute(
            fetch_diff_uri,
            "fetch-diff",
            fetch_diff_params,
            ExecuteOptions::default(),
        );

        let shared = self.shared.clone();
        let owner_cap = self.owner_self_cap.clone();

        async move {
            if let Some(e) = validation_err {
                return Err(e);
            }
            let fetch_result = fetch_fut.await?;
            if let Some(err) = SdkError::from_handler_result(
                &fetch_result,
                "reconcile: revision:fetch-diff",
            ) {
                return Err(err);
            }
            let envelope = fetch_result.result;
            let entities_ingested = count_envelope_included(&envelope);

            let merge_params = build_tree_merge_params(&envelope, &prefix, "source-wins");
            let local_identity = shared.identity_hash;
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared,
                Some(local_identity),
                std::collections::HashMap::new(),
                None,
                Some(owner_cap),
            );
            let merge_result = execute_fn(
                "system/tree".into(),
                "merge".into(),
                merge_params,
                ExecuteOptions::default(),
            )
            .await
            .map_err(|e| SdkError::HandlerError(e.to_string()))?;
            if let Some(err) = SdkError::from_handler_result(&merge_result, "reconcile: tree:merge")
            {
                return Err(err);
            }

            Ok(ReconcileResult {
                prefix,
                remote_peer_id,
                base_hash: last_seen,
                entities_ingested,
            })
        }
    }
}

fn pre_validate(remote_peer_id: &str, prefix: &str) -> Option<SdkError> {
    if remote_peer_id.is_empty() {
        return Some(SdkError::HandlerError(
            "reconcile: remote_peer_id is empty".into(),
        ));
    }
    if prefix.is_empty() {
        return Some(SdkError::HandlerError("reconcile: prefix is empty".into()));
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_fetch_diff_params(prefix: &str, base: Option<Hash>) -> Entity {
    // ECF order: base, prefix.
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    if let Some(h) = base {
        fields.push((
            entity_ecf::text("base"),
            ciborium::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    fields.push((entity_ecf::text("prefix"), entity_ecf::text(prefix)));
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/revision/fetch-diff-params", data)
        .expect("fetch-diff-params entity construction is infallible")
}

fn build_tree_merge_params(envelope: &Entity, prefix: &str, strategy: &str) -> Entity {
    // tree:merge accepts the envelope inline as `source_envelope`
    // (a `{type, data}` wrapper around the envelope entity). The
    // handler ingests `included` entities into the content store
    // and uses `root` as the source for the merge per
    // EXTENSION-TREE §5.2.
    //
    // We also pass `source_prefix` and `target_prefix` set to the
    // caller-supplied prefix so the merge applies entities under
    // the same prefix (the diff was computed for `prefix` on the
    // remote, and we want the same prefix locally).
    //
    // ECF order: source_envelope, source_prefix, strategy, target_prefix.
    let env_value: ciborium::Value =
        ciborium::de::from_reader(envelope.data.as_slice()).unwrap_or(ciborium::Value::Null);
    let source_envelope = ciborium::Value::Map(vec![
        (
            entity_ecf::text("data"),
            env_value,
        ),
        (
            entity_ecf::text("type"),
            entity_ecf::text(&envelope.entity_type),
        ),
    ]);

    let fields: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (entity_ecf::text("source_envelope"), source_envelope),
        (entity_ecf::text("source_prefix"), entity_ecf::text(prefix)),
        (entity_ecf::text("strategy"), entity_ecf::text(strategy)),
        (entity_ecf::text("target_prefix"), entity_ecf::text(prefix)),
    ];
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/tree/merge-params", data)
        .expect("tree merge-params entity construction is infallible")
}

fn count_envelope_included(entity: &Entity) -> usize {
    let val: ciborium::Value = match ciborium::de::from_reader(entity.data.as_slice()) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let map = match val.as_map() {
        Some(m) => m,
        None => return 0,
    };
    for (k, v) in map {
        if k.as_text() == Some("included") {
            if let Some(inc) = v.as_map() {
                return inc.len();
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Resource accessor helpers — defined locally so the reconcile module
// stays self-contained without leaking a clone-on-context to the SDK
// surface. PeerContext is Send+Sync via Arc<PeerShared>, so cloning
// just bumps refcounts.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn _suppress_unused_resource_target() {
    let _ = ResourceTarget {
        targets: vec![],
        exclude: vec![],
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::PeerContextBuilder;

    fn make_ctx() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    /// Empty `remote_peer_id` is rejected pre-dispatch with a wrapper-
    /// shaped error rather than dispatching the empty URI and waiting
    /// for a transport failure.
    #[tokio::test(flavor = "current_thread")]
    async fn reconcile_empty_remote_rejects() {
        let ctx = make_ctx();
        let r = ctx
            .reconcile_since_last_seen("", "/some-peer/app/", None)
            .await;
        match r {
            Err(SdkError::HandlerError(msg)) if msg.contains("remote_peer_id") => {}
            other => panic!("expected remote_peer_id rejection, got {:?}", other),
        }
    }

    /// Empty `prefix` is rejected pre-dispatch.
    #[tokio::test(flavor = "current_thread")]
    async fn reconcile_empty_prefix_rejects() {
        let ctx = make_ctx();
        let r = ctx
            .reconcile_since_last_seen("some-remote-id", "", None)
            .await;
        match r {
            Err(SdkError::HandlerError(msg)) if msg.contains("prefix") => {}
            other => panic!("expected prefix rejection, got {:?}", other),
        }
    }

    /// Dispatching against a remote peer-id the local peer isn't
    /// connected to surfaces a handler/transport error rather than
    /// panicking or returning success. Documents that the wrapper's
    /// failure path is well-behaved when the underlying transport
    /// can't reach the remote.
    ///
    /// (A real cross-peer reconcile test requires two connected
    /// peers + the D4 spec divergence resolved — see
    /// `docs/SPEC-AMBIGUITIES.md` "EXTENSION-REVISION fetch-diff D4".)
    #[tokio::test(flavor = "current_thread")]
    async fn reconcile_unknown_remote_surfaces_error() {
        let ctx = make_ctx();
        let r = ctx
            .reconcile_since_last_seen("nonexistent-peer-id", "/app/", None)
            .await;
        match r {
            Err(SdkError::HandlerError(_)) => {}
            Ok(ok) => panic!(
                "unexpected success against unconnected peer: {:?}",
                ok.entities_ingested
            ),
            Err(other) => panic!("unexpected wrapper-side error: {:?}", other),
        }
    }
}
