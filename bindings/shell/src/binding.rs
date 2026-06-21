//! `PeerBinding` — embedding-supplied adapter for peer state.
//!
//! Verbs that need to read peer-tier state (alias resolution, tree
//! ops, dispatch) take a `&dyn PeerBinding` argument; the embedding
//! implements the trait against its own peer-router type (egui's
//! `Peers`, Godot's palette context, standalone `entity-shell`'s
//! local peer handle).
//!
//! Phase 3b grows the trait as more verbs lift. Phase 3a-cd surface
//! covers only what `cd`'s alias resolution needs. Per
//! `GUIDE-SHELL-FRAMING.md` §3.6: minimal surface — the crate gets
//! what it needs to dispatch verbs, nothing more.

/// One entry in a `tree_listing` result. Crate-side type so the
/// `PeerBinding` trait does not force consumers to pull in
/// `entity_store::LocationEntry` (which carries a `Hash` — extra
/// dep weight verbs don't need today). Extend with optional fields
/// (`hash`, `entity_type`) when a verb forces them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeListingEntry {
    /// Fully qualified tree path (`/{peer_id}/...`).
    pub path: String,
}

/// Entity body + type as read from `PeerBinding::get_entity`. Crate-
/// side type so the trait doesn't require consumers to surface the
/// upstream `entity_entity::Entity` (which would pull `entity-entity`
/// + `entity-hash` into the crate's dep graph).
///
/// `content_hash` is the hex-encoded SHA-256 over the ECF-encoded
/// `{data, type}` — the same Hash the store keys entities by. Real
/// bindings surface it (Dom, Godot); test stubs may use any string
/// (empty when not relevant to the test).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityRead {
    /// Entity type tag (`app/state/setting`, etc.).
    pub entity_type: String,
    /// Raw CBOR bytes — `cat` runs `format::entity_data` over them to
    /// produce the displayable body.
    pub data: Vec<u8>,
    /// Hex-encoded content hash (see struct docs). May be empty when
    /// the binding doesn't surface the hash.
    pub content_hash: String,
}

/// One match in a `query` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMatch {
    pub path: String,
    pub entity_type: String,
}

/// Result of a `PeerBinding::query` call. `matches` is bounded by the
/// limit the verb requested; `total` is the unbounded match count;
/// `has_more` is `true` when `matches.len() < total`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResults {
    pub matches: Vec<QueryMatch>,
    pub total: usize,
    pub has_more: bool,
}

/// Embedding adapter exposing peer-router state to crate-side verbs.
///
/// The methods returning owned values (`Vec<String>`, `String`,
/// `Option<String>`) avoid forcing the embedding into a particular
/// borrow / locking shape — implementations are free to clone from
/// a held mutex, read from a snapshot, or build on demand.
pub trait PeerBinding {
    /// The peer this binding represents — the shell's bound peer.
    /// Used as the default tree-scope for verbs.
    fn peer_id(&self) -> &str;

    /// The session's primary peer id (the system peer; may equal
    /// `peer_id()` for primary-bound shells).
    fn primary_peer_id(&self) -> String;

    /// All local peer ids in the session, including the primary.
    /// Order is implementation-defined.
    fn peer_ids(&self) -> Vec<String>;

    /// Connected remote peer ids. May be empty when the embedding
    /// has no notion of remote connections (standalone binary).
    fn connected_peers(&self) -> Vec<String>;

    /// Display label for `peer_id`, when one has been set. Used by
    /// `@<alias>` resolution for case-insensitive label matching.
    fn peer_label(&self, peer_id: &str) -> Option<String>;

    /// List immediate children at `prefix` within `peer_id`'s tree.
    /// Empty `Vec` for missing or empty prefixes — verbs distinguish
    /// "empty directory" from "no such path" themselves (the location
    /// index treats them the same).
    fn tree_listing(&self, peer_id: &str, prefix: &str) -> Vec<TreeListingEntry>;

    /// Read the entity at `path` within `peer_id`'s tree, or `None`
    /// when no entity exists there. `cat` distinguishes "no such
    /// entity" from any other error via this `Option`.
    fn get_entity(&self, peer_id: &str, path: &str) -> Option<EntityRead>;

    /// Read the entity with `hash_hex` content hash from `peer_id`'s
    /// store, or `None` when no such entity is reachable. Used by
    /// `inspect dump`. Default returns `None` so bindings without
    /// hash-keyed lookup don't need to override.
    fn get_entity_by_hash(&self, _peer_id: &str, _hash_hex: &str) -> Option<EntityRead> {
        None
    }

    /// Display tag for the primary peer's transport arm
    /// (`"Direct"` / `"Worker"` in egui's multi-SDK router; embeddings
    /// without a meaningful arm distinction can return any short
    /// identifier or `"local"`). Reported by the `info` verb. Default
    /// implementation returns `"local"` so embeddings that don't care
    /// about the distinction don't need to override.
    fn primary_arm(&self) -> &'static str {
        "local"
    }

    /// Remove `peer_id` from the embedding's connection registry. Used
    /// by `disconnect`. Idempotent — calling for a peer not in the
    /// registry is a no-op (the verb pre-checks `connected_peers` and
    /// returns a friendly "no action" message in that case).
    ///
    /// Note: this is app-tier registry teardown only. Underlying
    /// transport teardown is upstream-SDK work tracked separately; the
    /// verb's user-facing message reflects that. Default
    /// implementation is a no-op so embeddings without a connection
    /// registry don't need to override.
    fn remove_connection(&self, peer_id: &str) {
        let _ = peer_id;
    }

    /// Open a connection from `from_peer` to a remote at `address`.
    /// On success, the future resolves to the connected remote's
    /// peer-id (the embedding records it in its connection registry
    /// before completing). On failure, returns a user-facing error
    /// string. Used by `connect`.
    ///
    /// Address parsing (`ws://`, `xworker://`, `memory://`, etc.) is
    /// the embedding's responsibility — the verb passes the string
    /// through unchanged. Default implementation returns an error so
    /// embeddings without network support (e.g., a standalone REPL
    /// against a local-only peer) don't need to override.
    fn connect_peer(
        &self,
        _from_peer: &str,
        _address: String,
    ) -> crate::runtime::BoxFuture<'static, Result<String, String>> {
        Box::pin(async { Err("connect: not supported by this binding".into()) })
    }

    /// Write an entity at `path` within `peer_id`'s tree. `params_text`
    /// is an optional JSON-shaped body — the embedding parses it into
    /// whatever shape its writer expects (CBOR-encoded entity body in
    /// egui's case). When `None`, an empty/null body is written.
    ///
    /// Returns the user-facing error string on construction or JSON
    /// parse failure; success returns `Ok(())`. Default returns an
    /// error so embeddings without a writer don't need to override.
    fn put_entity(
        &self,
        _peer_id: &str,
        _path: &str,
        _entity_type: &str,
        _params_text: Option<String>,
    ) -> Result<(), String> {
        Err("put: not supported by this binding".into())
    }

    /// Remove the entity at `path` within `peer_id`'s tree. Used by
    /// `rm`. Embeddings without write capability can leave the
    /// default (no-op); successful removal is acked synchronously.
    fn remove_entity(&self, _peer_id: &str, _path: &str) {}

    /// Query for entities matching `type_filter` (empty = no type
    /// filter) within `peer_id`'s tree, capped at `limit`. Used by
    /// `query`. Default returns an error.
    fn query(
        &self,
        _peer_id: &str,
        _type_filter: &str,
        _limit: usize,
    ) -> crate::runtime::BoxFuture<'static, Result<QueryResults, String>> {
        Box::pin(async { Err("query: not supported by this binding".into()) })
    }

    /// Count entities matching `type_filter` (empty = total). Used by
    /// `count`. Default returns an error.
    fn count(
        &self,
        _peer_id: &str,
        _type_filter: &str,
    ) -> crate::runtime::BoxFuture<'static, Result<usize, String>> {
        Box::pin(async { Err("count: not supported by this binding".into()) })
    }

    /// Execute a handler op against `peer_id`'s tree. Used by `exec`.
    /// The future resolves to a handler-supplied summary string on
    /// success (rendered as the `Dispatch::Complete` chunk) or a
    /// stringified error on failure.
    ///
    /// `params_text` carries any JSON-shaped parameter blob the user
    /// supplied after `<operation>`. The embedding parses it into
    /// whatever shape its dispatch expects (CBOR-encoded
    /// `system/params` entity in egui's case); a `Usage`-style
    /// failure is the embedding's responsibility if the blob doesn't
    /// parse. Keeping JSON parsing embedding-side avoids pulling
    /// `serde_json` into the crate.
    ///
    /// Default returns an error.
    fn execute(
        &self,
        _peer_id: &str,
        _handler_uri: String,
        _operation: String,
        _params_text: Option<String>,
    ) -> crate::runtime::BoxFuture<'static, Result<String, String>> {
        Box::pin(async { Err("exec: not supported by this binding".into()) })
    }

    /// Evaluate the compute expression at `expr_path` within `peer_id`'s
    /// tree. Returns a multi-line human-formatted string (the rendered
    /// info rows) on success, or a user-facing error message on failure.
    ///
    /// `budget` is the optional per-call ops cap (forwards to the SDK's
    /// `EvalOptions.budget`); when `None`, the handler ceiling applies.
    /// Default returns an error so embeddings without `system/compute`
    /// don't need to override.
    fn compute_eval(
        &self,
        _peer_id: &str,
        _expr_path: String,
        _budget: Option<u64>,
    ) -> crate::runtime::BoxFuture<'static, Result<String, String>> {
        Box::pin(async { Err("compute eval: not supported by this binding".into()) })
    }

    /// Install a reactive subgraph rooted at `root_expression_path`.
    /// `result_path` overrides where reactive results are written
    /// (default `<root>/result`).
    ///
    /// On success returns `(subgraph_path, result_path)` — both are
    /// fully-qualified tree paths the handler chose. Default returns
    /// an error.
    fn compute_install(
        &self,
        _peer_id: &str,
        _root_expression_path: String,
        _result_path: Option<String>,
    ) -> crate::runtime::BoxFuture<'static, Result<(String, String), String>> {
        Box::pin(async { Err("compute install: not supported by this binding".into()) })
    }

    /// Uninstall the subgraph at `subgraph_path`. Default returns an
    /// error.
    fn compute_uninstall(
        &self,
        _peer_id: &str,
        _subgraph_path: String,
    ) -> crate::runtime::BoxFuture<'static, Result<(), String>> {
        Box::pin(async { Err("compute uninstall: not supported by this binding".into()) })
    }

    /// List installed subgraphs for `peer_id`. Each row carries
    /// `(subgraph_path, root_expression_path, status)`. Async so the
    /// Worker arm can satisfy it via an L1 query round-trip; the Direct
    /// arm resolves immediately. Default returns an empty list.
    fn compute_list(
        &self,
        _peer_id: &str,
    ) -> crate::runtime::BoxFuture<'static, Result<Vec<(String, String, String)>, String>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Show one subgraph's metadata as labeled rows ready for
    /// `VerbOutput::Info`-style rendering. `Ok(None)` when no subgraph is
    /// bound at `subgraph_path`. Async so the Worker arm can satisfy it
    /// via an on-demand `Get`; the Direct arm resolves immediately.
    /// Default returns `Ok(None)`.
    fn compute_show(
        &self,
        _peer_id: &str,
        _subgraph_path: String,
    ) -> crate::runtime::BoxFuture<'static, Result<Option<Vec<(String, String)>>, String>> {
        Box::pin(async { Ok(None) })
    }

    /// Bootstrap this peer's identity stack. `threshold`/`label` come
    /// from the verb's flag args; Phase 1 SDK rejects `threshold > 1`
    /// with `multi_signer_unsupported` — surface that error verbatim
    /// rather than pre-validating here.
    ///
    /// Returns labeled rows describing the outcome (Bootstrapped vs
    /// AlreadyBootstrapped) — verbs format these as
    /// `VerbOutput::Info`. Default returns an error.
    fn bootstrap_identity(
        &self,
        _peer_id: &str,
        _threshold: usize,
        _label: Option<String>,
    ) -> crate::runtime::BoxFuture<'static, Result<Vec<(String, String)>, String>> {
        Box::pin(async { Err("bootstrap: not supported by this binding".into()) })
    }

    /// Sync L0 status read. Returns labeled rows describing the
    /// current bootstrap state (`bootstrapped`, `identity`, `quorum`,
    /// `peer_config`). Default returns empty.
    fn bootstrap_status(&self, _peer_id: &str) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Export this peer's identity as a portable CBOR bundle. Returns
    /// the encoded bytes ready for hex-encoding by the verb. Default
    /// returns an error.
    fn export_identity_bundle(
        &self,
        _peer_id: &str,
    ) -> Result<Vec<u8>, String> {
        Err("bootstrap export: not supported by this binding".into())
    }

    /// Decode CBOR-encoded bundle bytes + restore the identity stack.
    /// Returns labeled rows describing the restored stack. Default
    /// returns an error.
    fn restore_identity_bundle(
        &self,
        _peer_id: &str,
        _bundle_cbor: Vec<u8>,
    ) -> crate::runtime::BoxFuture<'static, Result<Vec<(String, String)>, String>> {
        Box::pin(async { Err("bootstrap import: not supported by this binding".into()) })
    }
}
