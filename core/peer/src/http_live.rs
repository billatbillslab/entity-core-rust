//! HTTP live + serving transport (`system/peer/transport/http`,
//! `system/peer/transport/http-poll` — EXTENSION-NETWORK §6.5).
//!
//! Server-side listener that composes:
//!
//! - **Live POST EXECUTE** (Chunk D, §6.5.2c, Amendment 3)
//!   on a configured `execute_path`. Each request body is one bare
//!   ECF-encoded envelope; the response body is one bare envelope.
//!   HTTP message framing (`Content-Length` / `Transfer-Encoding:
//!   chunked`) delimits the body. **POST-only, half-duplex, no
//!   server-push in v1.**
//! - **Serving-mode poll routes** (Chunk E, per the serving-mode
//!   content-scope ruling, un-gated)
//!   on a configured `poll_prefix`:
//!     - `GET <prefix>/content/{hex(H)}` — content-by-hash,
//!       hash-knowledge-as-auth + serving-side scope predicate.
//!     - `GET <prefix>/tree/{absolute-path}` — `system/tree:get`
//!       dispatch (capability-gated; TREE owns its own auth model).
//!     - `GET <prefix>/manifest/{path}` — 501 stub until
//!       EXTENSION-MANIFEST §4 lands (Chunk E §7 explicit defer).
//!
//! Two deployment postures are supported:
//!
//! - **Posture 1 (RECOMMENDED) — isolated port.** Bind one
//!   `HttpLiveListener` for live POST + a separate one (constructed
//!   via [`HttpLiveListener::bind_poll`]) for serving. Clean
//!   abstraction; trivial reverse-proxy / CDN fronting.
//! - **Posture 2 — same listener (G2 demux, for 80/443 reuse).** One
//!   listener handles both: configure via [`HttpLiveListener::bind`]
//!   then [`HttpLiveListener::with_poll_prefix`]. Path prefix (default
//!   `/poll`) keeps the namespaces orthogonal — G4 advisory says
//!   operator picks a non-colliding live path.
//!
//! **Cross-impl framing pin (Amendment 3).** The V7 §1.6 4-byte TCP
//! length prefix **MUST NOT** be applied to live POST bodies. §1.6
//! declares framing per-transport; HTTP frames the body natively, so
//! an inner prefix is redundant and creates two conflicting length
//! authorities (and breaks fetch/curl/CDN/proxy composition — the
//! ecosystem interop that is the `http` profile's reason to exist). A
//! bad body decode is the substrate-level `400`; entity-protocol
//! errors instead travel INSIDE the response envelope under `200`.
//!
//! **Live POST session correlation** matches Go's
//! `httplive.SessionHeader`:
//! - `X-Entity-Session` header carries a server-allocated opaque ID.
//!   Server returns it on every response; client echoes on subsequent
//!   POSTs so the multi-step `HELLO → AUTHENTICATE → EXECUTE` flow
//!   can spread across requests per §5.3 ("caps accrue across the
//!   request sequence").
//! - Per-session state TTL: idle sessions evict after
//!   [`DEFAULT_SESSION_TTL`] (30 min). **ID format + TTL value are
//!   impl/operator choices, NOT cross-impl pins** (ruling §2)
//!   — ID is server-opaque (client never parses it),
//!   TTL is operator-tunable.
//!
//! **Serving-mode scope** is the load-bearing arch lever (ruling
//! §1.2): the route's `in_scope(H)` predicate decides which hashes
//! the route answers for. v1 ships [`scope::NamespaceScope`]
//! (tree-binding presence under `system/content/{namespace}`);
//! closure + whole-store land as additional [`scope::ScopePredicate`]
//! impls without touching the handler. **Identical 404 for
//! out-of-scope vs not-held** (T4 mitigation, ruling §1.3) — the
//! route is not a private-holdings oracle.
//!
//! **Body shape — verify-by-rehash** (arch ruling 1b5c125 §1).
//! The `/content/{hex(H)}` response body is the **full
//! entity ECF** — `ecf_for_hash(type, data)`, the exact bytes that
//! produce H under `Hash::compute`. `Content-Type: application/cbor`.
//! Anything else (e.g., the inner `data` payload) breaks the
//! content-addressed contract — the consumer can't verify against
//! the URL hash. The "raw octet-stream" instinct belongs to Route 2
//! (rendering / consumer-side reassembly + descriptor MIME), NOT
//! this route.
//!
//! **Wrapper, NOT BRIDGE-HTTP.** The bytes on the wire ARE entity
//! envelopes (Mechanism A); BRIDGE-HTTP (Mechanism B) is a
//! structurally distinct surface for foreign content.
//!
//! **TLS termination is out of scope** — operators front this
//! listener with a reverse proxy (nginx, Caddy, ALB, ...) for HTTPS.
//! Listener itself speaks plain HTTP/1.1. Foreign request-side auth
//! (OAuth, Basic, mTLS) is also reverse-proxy concern (ruling §1.4);
//! the listener serves the bytes, the proxy gates the request.
//!
//! Native-only; the WASM target's HTTP path is the browser's
//! `fetch()` which lives in `bindings/wasm-worker-host` + egui-rust.

#![cfg(all(feature = "http-live", not(target_arch = "wasm32")))]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use entity_hash::Hash;
use entity_protocol::Connection;
use entity_wire::{decode_envelope, encode_envelope};

use crate::connection::dispatch_session_envelope;
use crate::{PeerError, PeerShared};

pub mod scope;

pub use scope::{CapTokenScope, ClosureScope, NamespaceScope, ScopePredicate};

/// HTTP header used to correlate multiple POSTs into one logical
/// connection sequence. Server returns its allocated ID on the first
/// response; connector echoes it on subsequent POSTs. Pinned wire
/// constant — must match Go's `httplive.SessionHeader`.
pub const SESSION_HEADER: &str = "X-Entity-Session";

/// Default idle-session TTL — 30 minutes. Matches Go's
/// `DefaultSessionTTL`. Operators MAY override via
/// [`HttpLiveListener::with_session_ttl`].
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(30 * 60);

/// Default poll-route prefix when poll routes are mounted alongside
/// the live POST listener (Posture 2). Operator MAY override via
/// [`HttpLiveListener::with_poll_prefix`]. For Posture 1 (isolated
/// port), the convention is an empty prefix so poll routes sit at
/// the root.
pub const DEFAULT_POLL_PREFIX: &str = "/poll";

/// Default leaf-entity URL suffix per EXTENSION-NETWORK §6.5.3
/// (Amendment 5). Consumers append this to the tree path to address
/// the bound *entity* (`{path}.bin`). Operator MAY override; MUST
/// differ from [`DEFAULT_TREE_LISTING_SUFFIX`].
pub const DEFAULT_TREE_LEAF_SUFFIX: &str = ".bin";

/// Default listing URL suffix per EXTENSION-NETWORK §6.5.3
/// (Amendment 5). Consumers append this to the tree path to address
/// the *listing* (`{path}.list`). Distinct from the leaf suffix so
/// every URL is a concrete object key (no trailing-slash form,
/// which doesn't survive static-CDN slash normalization).
pub const DEFAULT_TREE_LISTING_SUFFIX: &str = ".list";

/// Default request-URL byte cap per EXTENSION-NETWORK §6.5.3.1
/// status table (Amendment 5) — `RECOMMENDED 8 KB per RFC 7230
/// §3.1.1`. Above this, the route returns 414. Operator MAY override.
pub const DEFAULT_MAX_URL_BYTES: usize = 8192;

/// Per-session state held by the server: the `entity_protocol::
/// Connection` state machine + last-touched stamp for TTL eviction.
struct SessionEntry {
    conn: Connection,
    touched: Instant,
}

/// Goroutine-safe session map keyed by the session ID returned via
/// `X-Entity-Session`.
pub(crate) struct SessionStore {
    inner: Mutex<HashMap<String, Arc<Mutex<SessionEntry>>>>,
    ttl: Duration,
}

impl SessionStore {
    fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Look up an existing session by ID, or allocate a fresh one.
    /// Returns the (possibly new) session ID + the session state.
    /// Evicts expired sessions opportunistically on each call.
    async fn get_or_create(
        &self,
        id: Option<&str>,
        local_peer_id: entity_crypto::PeerId,
    ) -> (String, Arc<Mutex<SessionEntry>>) {
        let mut map = self.inner.lock().await;
        // Evict expired entries.
        let cutoff = Instant::now()
            .checked_sub(self.ttl)
            .unwrap_or_else(Instant::now);
        let mut to_remove: Vec<String> = Vec::new();
        for (k, v) in map.iter() {
            // Only evict if we can acquire the lock without contention —
            // a session mid-dispatch is not expired by definition.
            if let Ok(guard) = v.try_lock() {
                if guard.touched < cutoff {
                    to_remove.push(k.clone());
                }
            }
        }
        for k in to_remove {
            map.remove(&k);
        }

        if let Some(id) = id {
            if let Some(entry) = map.get(id).cloned() {
                // Touch the entry to refresh TTL.
                {
                    let mut guard = entry.lock().await;
                    guard.touched = Instant::now();
                }
                return (id.to_string(), entry);
            }
        }
        let new_id = alloc_session_id();
        let entry = Arc::new(Mutex::new(SessionEntry {
            conn: Connection::new(local_peer_id),
            touched: Instant::now(),
        }));
        map.insert(new_id.clone(), entry.clone());
        (new_id, entry)
    }
}

fn alloc_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(32);
    for b in &bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Internal route configuration. Either or both of `execute_path` and
/// `poll_prefix` may be set; if both are unset the listener answers
/// 404 to everything (which is a configuration bug — constructors
/// always set at least one).
#[derive(Clone)]
struct Routes {
    /// POST `<execute_path>` → live EXECUTE dispatch. `None` disables
    /// the live POST route entirely (Posture 1: poll-only listener).
    execute_path: Option<String>,
    /// Poll routes mounted under this path prefix. `None` disables
    /// poll routes; `Some("")` mounts at the root (Posture 1
    /// convention); `Some("/poll")` mounts under `/poll` (Posture 2
    /// default).
    poll_prefix: Option<String>,
    /// Serving-side scope predicate for content-by-hash. `None` means
    /// no scope configured — every `GET /content/{...}` returns 404
    /// (the "serving not enabled" posture).
    scope: Option<Arc<dyn ScopePredicate>>,
    /// Leaf-entity URL suffix per §6.5.3 (Amendment 5). Default
    /// `.bin`; MUST differ from `tree_listing_suffix`.
    tree_leaf_suffix: String,
    /// Listing URL suffix per §6.5.3 (Amendment 5). Default `.list`.
    tree_listing_suffix: String,
    /// Optional configured manifest hash. `Some(H)` → `MANIFEST_GET`
    /// serves the entity with content_hash `H` from the content
    /// store; `None` → `/manifest` ⇒ 404 (no manifest published, per
    /// §6.5.3.1 MANIFEST_GET body bullet).
    manifest_hash: Option<Hash>,
    /// Max URL byte length per §6.5.3.1 status table (Amendment 5).
    /// `0` ⇒ unbounded; above the cap ⇒ 414.
    max_url_bytes: usize,
}

/// Server-side listener for the `http` + `http-poll` transport
/// profiles. One listener instance binds one TCP socket and routes
/// requests by (method, path) per [`Routes`].
///
/// **Construction:**
/// - [`HttpLiveListener::bind`] — Chunk D shape, POST EXECUTE on a
///   configured URL path. No serving routes.
/// - [`HttpLiveListener::bind_poll`] — Posture 1 (isolated port for
///   serving). Poll routes only; no POST EXECUTE.
/// - [`HttpLiveListener::with_poll_prefix`] / [`HttpLiveListener::with_scope`]
///   — extend an existing listener with poll routes (Posture 2).
pub struct HttpLiveListener {
    inner: TcpListener,
    bound_addr: SocketAddr,
    routes: Routes,
    sessions: Arc<SessionStore>,
}

impl HttpLiveListener {
    /// Bind the listener on `addr` (e.g., `"127.0.0.1:0"` for an
    /// ephemeral port, `"0.0.0.0:4080"` for a fixed port). The
    /// `url_path` is the path the listener accepts POSTs on (e.g.,
    /// `"/entity"`); anything else returns 404. The path is operator
    /// choice (G1) and must match what the published profile's
    /// `endpoint.url` advertises.
    pub async fn bind(addr: &str, url_path: impl Into<String>) -> Result<Self, PeerError> {
        let path = normalize_route_path(url_path.into());
        bind_inner(addr, Some(path), None).await
    }

    /// Bind the listener for **serving-mode only** (Posture 1:
    /// isolated port, no live POST EXECUTE). Poll routes mount at the
    /// root (or under `poll_prefix` if the operator wants nested
    /// routes on the isolated port — atypical).
    ///
    /// Without a configured [`ScopePredicate`] (set via
    /// [`Self::with_scope`]), `GET /content/{hex(H)}` returns 404 —
    /// serving is "enabled but no scope," which is a configuration
    /// bug at the operator level.
    pub async fn bind_poll(
        addr: &str,
        poll_prefix: impl Into<String>,
    ) -> Result<Self, PeerError> {
        let prefix = normalize_prefix(poll_prefix.into());
        bind_inner(addr, None, Some(prefix)).await
    }

    /// Extend an existing live-POST listener with poll routes mounted
    /// under `prefix` (Posture 2 — same listener for live + serving).
    /// Pass [`DEFAULT_POLL_PREFIX`] for the conventional `/poll`.
    pub fn with_poll_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.routes.poll_prefix = Some(normalize_prefix(prefix.into()));
        self
    }

    /// Configure the serving-side scope predicate. Without a scope,
    /// content-by-hash GETs return 404. v1 ships
    /// [`NamespaceScope`]; closure + whole-store predicates land
    /// without touching the handler shape (arch ruling §4 seam).
    pub fn with_scope(mut self, scope: Arc<dyn ScopePredicate>) -> Self {
        self.routes.scope = Some(scope);
        self
    }

    /// Override the suffixes used for entity vs listing URLs
    /// (Amendment 5). Defaults are [`DEFAULT_TREE_LEAF_SUFFIX`]
    /// (`.bin`) and [`DEFAULT_TREE_LISTING_SUFFIX`] (`.list`). The
    /// two MUST differ — §6.5.3 makes the distinct-suffixes
    /// REQUIRED. Returns an error if they collide.
    pub fn with_suffixes(
        mut self,
        leaf: impl Into<String>,
        listing: impl Into<String>,
    ) -> Result<Self, PeerError> {
        let leaf = leaf.into();
        let listing = listing.into();
        if leaf == listing {
            return Err(PeerError::BuildError(format!(
                "tree_leaf_suffix and tree_listing_suffix MUST differ (§6.5.3 Amendment 5), got {:?} for both",
                leaf
            )));
        }
        if leaf.is_empty() || listing.is_empty() {
            return Err(PeerError::BuildError(
                "tree suffixes MUST be non-empty (§6.5.3 Amendment 5)".to_string(),
            ));
        }
        self.routes.tree_leaf_suffix = leaf;
        self.routes.tree_listing_suffix = listing;
        Ok(self)
    }

    /// Configure the manifest hash served by `MANIFEST_GET` per
    /// §6.5.3.1 Amendment 5. Pass the content hash of the signed
    /// manifest entity (typically `system/peer/published-root` per
    /// PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE). Without this,
    /// `/manifest` returns 404 (none published).
    pub fn with_manifest_hash(mut self, hash: Hash) -> Self {
        self.routes.manifest_hash = Some(hash);
        self
    }

    /// Override the URL byte cap (§6.5.3.1 status table). Default
    /// is [`DEFAULT_MAX_URL_BYTES`] (8 KB, RFC 7230 §3.1.1). Pass
    /// `0` to disable the cap entirely (not recommended — the cap
    /// is a parser-DoS guard).
    pub fn with_max_url_bytes(mut self, max: usize) -> Self {
        self.routes.max_url_bytes = max;
        self
    }

    /// Override the idle-session TTL. Default is
    /// [`DEFAULT_SESSION_TTL`] (30 minutes). Only relevant when the
    /// listener answers live POST.
    pub fn with_session_ttl(mut self, ttl: Duration) -> Self {
        self.sessions = Arc::new(SessionStore::new(ttl));
        self
    }

    /// The actual bound `SocketAddr` (useful for port-0
    /// auto-assignment).
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// The accepted POST URL path (with leading slash) for live
    /// EXECUTE, or `None` if this listener is poll-only.
    pub fn url_path(&self) -> Option<&str> {
        self.routes.execute_path.as_deref()
    }

    /// The poll-route prefix (with leading slash, possibly empty), or
    /// `None` if poll routes are not enabled on this listener.
    pub fn poll_prefix(&self) -> Option<&str> {
        self.routes.poll_prefix.as_deref()
    }

    /// Run the accept loop. Each accepted TCP connection is fed to
    /// hyper's HTTP/1.1 implementation and serviced by
    /// [`handle_http_request`]. Returns only on listener error
    /// (network failure, OS-level abort). Connection-level errors are
    /// logged and the loop continues.
    pub async fn serve(self, shared: Arc<PeerShared>) -> Result<(), PeerError> {
        let routes = Arc::new(self.routes);
        let sessions = self.sessions;
        loop {
            let (stream, peer_addr) = self.inner.accept().await.map_err(|e| {
                PeerError::ConnectionError(format!("http_live accept: {}", e))
            })?;
            tracing::debug!(remote = %peer_addr, "http_live: accepted connection");

            let io = TokioIo::new(stream);
            let shared = shared.clone();
            let routes = routes.clone();
            let sessions = sessions.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let shared = shared.clone();
                    let routes = routes.clone();
                    let sessions = sessions.clone();
                    async move {
                        Ok::<_, Infallible>(
                            handle_http_request(req, shared, &routes, sessions).await,
                        )
                    }
                });
                if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                    tracing::debug!(remote = %peer_addr, error = %e, "http_live: connection ended with error");
                }
            });
        }
    }
}

async fn bind_inner(
    addr: &str,
    execute_path: Option<String>,
    poll_prefix: Option<String>,
) -> Result<HttpLiveListener, PeerError> {
    let inner = TcpListener::bind(addr)
        .await
        .map_err(|e| PeerError::BuildError(format!("http_live bind {}: {}", addr, e)))?;
    let bound_addr = inner
        .local_addr()
        .map_err(|e| PeerError::BuildError(format!("http_live local_addr: {}", e)))?;
    Ok(HttpLiveListener {
        inner,
        bound_addr,
        routes: Routes {
            execute_path,
            poll_prefix,
            scope: None,
            tree_leaf_suffix: DEFAULT_TREE_LEAF_SUFFIX.to_string(),
            tree_listing_suffix: DEFAULT_TREE_LISTING_SUFFIX.to_string(),
            manifest_hash: None,
            max_url_bytes: DEFAULT_MAX_URL_BYTES,
        },
        sessions: Arc::new(SessionStore::new(DEFAULT_SESSION_TTL)),
    })
}

/// Normalize a route path — leading slash forced; trailing slash
/// stripped (empty string remains empty, single "/" remains "/").
fn normalize_route_path(mut p: String) -> String {
    if !p.starts_with('/') {
        p = format!("/{}", p);
    }
    // Don't strip the lone "/" — caller may genuinely want root.
    if p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

/// Normalize a path *prefix* — same as route_path but the empty
/// string is preserved as "" (mount-at-root convention for Posture 1).
fn normalize_prefix(p: String) -> String {
    if p.is_empty() {
        return p;
    }
    normalize_route_path(p)
}

/// Top-level HTTP request router.
///
/// Routing rules:
/// 1. URL byte cap (§6.5.3.1 Amendment 5) — `max_url_bytes` exceeded → 414.
/// 2. If the path matches `execute_path` exactly → live POST EXECUTE
///    (POST only; other methods → 405 Allow: POST).
/// 3. Else if the path starts with `poll_prefix` → Amendment-5 demux
///    (literal-then-peer-id-parse, see [`route_poll`]).
///    GET only on poll routes (other methods → 405 Allow: GET).
/// 4. Else → 404.
///
/// Per spec §5.3 "subscribe-unsupported is conformant" — there's no
/// server-push channel on plain HTTP; consumers track tree changes by
/// polling the live POST or the poll routes.
async fn handle_http_request(
    req: Request<Incoming>,
    shared: Arc<PeerShared>,
    routes: &Routes,
    sessions: Arc<SessionStore>,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // 1. URL length cap per §6.5.3.1 Amendment 5 (parser-DoS guard).
    if routes.max_url_bytes > 0 && path.len() > routes.max_url_bytes {
        return text_response(
            StatusCode::URI_TOO_LONG,
            format!(
                "URI exceeds configured cap: {} > {}",
                path.len(),
                routes.max_url_bytes
            ),
        );
    }

    // 2. Live POST EXECUTE route.
    if let Some(ref exec) = routes.execute_path {
        if path == *exec {
            if method == Method::POST {
                return handle_execute_post(req, shared, sessions).await;
            }
            return method_not_allowed(Method::GET, "POST");
        }
    }

    // 3. Poll routes (Amendment 5 demux).
    if let Some(ref prefix) = routes.poll_prefix {
        if let Some(rest) = strip_prefix_with_boundary(&path, prefix) {
            return route_poll(method, rest, shared, routes).await;
        }
    }

    // 4. Unknown path.
    text_response(StatusCode::NOT_FOUND, format!("not found: {}", path))
}

/// Match `path` against `prefix` where the prefix MUST be either an
/// exact match (followed by end-of-string) or followed by `/`. This
/// prevents `/poll` from matching `/poller/foo` as if the prefix
/// applied. The empty prefix matches everything (Posture 1 mount-at-
/// root).
fn strip_prefix_with_boundary<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        return Some(path);
    }
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() || rest.starts_with('/') {
        Some(rest)
    } else {
        None
    }
}

/// Dispatch a poll-route request after the prefix has been stripped.
/// `rest` is the portion of the path AFTER the prefix (so for
/// `/poll/foo` with prefix `/poll`, `rest = "/foo"`).
///
/// **Amendment 5 demux (§6.5.6) — literal-then-peer-id-parse, in
/// order.** Not a length threshold; the *check* is literal-then-parse:
///   1. literal `content/{hex33}` → CONTENT_GET
///   2. literal `manifest` (terminal — `/manifest/...` ⇒ 404) → MANIFEST_GET
///   3. literal `peers{listing_suffix}` → all-peers universal-tree-root listing
///      (bare `peers` ⇒ 404)
///   4. else parse first segment as a peer-id → TREE_GET dispatch
///      (entity vs listing by suffix per §6.5.3.1)
///   5. else 404
async fn route_poll(
    method: Method,
    rest: &str,
    shared: Arc<PeerShared>,
    routes: &Routes,
) -> Response<Full<Bytes>> {
    if method != Method::GET {
        return method_not_allowed(method, "GET");
    }

    // 1. Literal `content/{hex33}`.
    if let Some(hex) = rest.strip_prefix("/content/") {
        return handle_content_get(hex, shared, routes.scope.as_ref()).await;
    }

    // 2. Literal `manifest` (terminal; `/manifest/` or anything under
    //    it ⇒ 404 — singular per §6.5.3.1 MANIFEST_GET).
    if rest == "/manifest" {
        return handle_manifest_get(shared, routes).await;
    }

    // 3. Literal `peers{listing_suffix}` (e.g. `/peers.list` default)
    //    → all-peers universal-tree-root listing. Bare `peers` ⇒ 404.
    let peers_listing = format!("/peers{}", routes.tree_listing_suffix);
    if rest == peers_listing {
        return handle_all_peers_listing(shared, routes).await;
    }

    // 4. else parse first segment as a peer-id → TREE_GET.
    //    First strip the leading `/` and split off the first segment.
    let stripped = rest.strip_prefix('/').unwrap_or(rest);
    if stripped.is_empty() {
        return not_found_opaque();
    }
    let (first_seg, tail) = match stripped.find('/') {
        Some(i) => (&stripped[..i], &stripped[i..]), // tail keeps leading `/`
        None => (stripped, ""),
    };

    // Strip exactly one recognized suffix from the LAST URL segment to
    // tell apart entity vs listing. We do this before the peer-id parse
    // because `peer_id` itself may end in a suffix-shaped substring
    // that is part of its base58 encoding — we MUST strip from the URL
    // form, not from the parsed id.
    let (first_seg_unsuffixed, listing_at_root) =
        if first_seg.ends_with(&routes.tree_listing_suffix) {
            (
                &first_seg[..first_seg.len() - routes.tree_listing_suffix.len()],
                true,
            )
        } else if first_seg.ends_with(&routes.tree_leaf_suffix) {
            (
                &first_seg[..first_seg.len() - routes.tree_leaf_suffix.len()],
                false,
            )
        } else if !tail.is_empty() {
            // Multi-segment path: the suffix lives on the LAST segment,
            // not the first; we'll strip it below in handle_tree_get.
            (first_seg, false)
        } else {
            // Single-segment with no suffix ⇒ 404 (bare unknown).
            return not_found_opaque();
        };

    // Parse the (un-suffixed) first segment as a peer-id.
    let pid = entity_crypto::PeerId::from(first_seg_unsuffixed);
    if pid.validate().is_err() {
        // Not a peer-id and not a reserved literal ⇒ 404.
        return not_found_opaque();
    }

    if tail.is_empty() {
        // The whole URL is `/{peer_id}{suffix}`.
        if listing_at_root {
            // `/{peer_id}.list` ⇒ peer-root listing.
            return handle_peer_root_listing(&pid, shared, routes).await;
        } else {
            // `/{peer_id}.bin` ⇒ 404 — peer roots are directories
            // (V7 §1.4; §6.5.3.1 explicit).
            return not_found_opaque();
        }
    }

    // Multi-segment: `/{peer_id}/...{suffix}` — dispatch by the
    // last-segment suffix.
    handle_tree_get(&pid, tail, shared, routes).await
}

/// Handle a POST EXECUTE on the live route.
async fn handle_execute_post(
    req: Request<Incoming>,
    shared: Arc<PeerShared>,
    sessions: Arc<SessionStore>,
) -> Response<Full<Bytes>> {
    // Extract the session header (if any) BEFORE consuming the request.
    let client_session = req
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Read the body.
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "http_live: failed to read request body");
            return text_response(
                StatusCode::BAD_REQUEST,
                format!("body read failed: {}", e),
            );
        }
    };

    // Decode the body as a bare ECF envelope. Per EXTENSION-NETWORK
    // §6.5.2c Amendment 3: HTTP body is the bare
    // envelope; HTTP's own Content-Length/chunked frames it; the V7
    // §1.6 TCP length prefix MUST NOT be applied.
    let envelope = match decode_envelope(body_bytes.as_ref()) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "http_live: envelope decode failed");
            return text_response(
                StatusCode::BAD_REQUEST,
                format!("envelope decode failed: {}", e),
            );
        }
    };

    // Look up or allocate the session — chooses by Connection state
    // whether to run hello / authenticate / dispatch.
    let local_pid = shared.keypair.peer_id();
    let (session_id, session_entry) = sessions
        .get_or_create(client_session.as_deref(), local_pid)
        .await;

    let response_envelope = {
        let mut guard = session_entry.lock().await;
        guard.touched = Instant::now();
        let SessionEntry { conn, .. } = &mut *guard;
        dispatch_session_envelope(&envelope, conn, shared).await
    };

    let response_bytes = encode_envelope(&response_envelope);

    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/cbor")
        .header(SESSION_HEADER, session_id)
        .body(Full::new(Bytes::from(response_bytes)))
        .unwrap_or_else(|_| {
            text_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed".into())
        })
}

/// Handle GET `<prefix>/content/{hex(H)}` per Chunk E §4. Returns:
/// - 400 on malformed hex.
/// - 404 (identical body) when `scope.in_scope(H)` is false OR the
///   content store doesn't hold `H` — T4 mitigation, no presence
///   oracle (arch ruling §1.3).
/// - 200 + raw bytes + `application/octet-stream` +
///   `Cache-Control: immutable, max-age=...` + `ETag: "{hex(H)}"`
///   when in-scope and held.
async fn handle_content_get(
    hex_path_part: &str,
    shared: Arc<PeerShared>,
    scope: Option<&Arc<dyn ScopePredicate>>,
) -> Response<Full<Bytes>> {
    // Hex-decode the path segment to a Hash. A 32-byte digest is 64
    // hex chars; we accept exactly that. Anything else → 400.
    let h = match parse_hex_hash(hex_path_part) {
        Ok(h) => h,
        Err(msg) => {
            return text_response(StatusCode::BAD_REQUEST, format!("malformed hash: {}", msg));
        }
    };

    // Without a scope configured, the route is "enabled but not
    // populated" — every request 404s. This is the same 404 body the
    // out-of-scope and not-held cases use (no presence oracle).
    let scope = match scope {
        Some(s) => s,
        None => return not_found_opaque(),
    };

    // Scope check first. Bail with the same 404 whether out-of-scope
    // or not-held (T4).
    match scope.in_scope(&h, &shared).await {
        Ok(true) => {}
        Ok(false) => return not_found_opaque(),
        Err(e) => {
            tracing::warn!(error = %e, "http_live: scope predicate errored");
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scope predicate error".to_string(),
            );
        }
    }

    // In scope — try the content store.
    let entity = match shared.content_store.get(&h) {
        Some(e) => e,
        None => return not_found_opaque(),
    };

    // **Body shape — arch ruling 1b5c125 §1.** The
    // body is the **full entity ECF** — i.e., the exact bytes that
    // `Hash::compute(type, data)` hashes over. The content-addressed
    // contract IS verify-by-rehash (Mechanism A): the consumer
    // recomputes SHA-256(ECF({type, data})) and trusts the bytes
    // only if they re-hash to the URL-supplied H. Returning anything
    // else (e.g., the inner `entity.data` payload, dropping `type`)
    // means the route literally isn't content-addressed — a hostile
    // CDN could substitute. application/cbor reflects the wrapped
    // entity ECF. The "binaries-over-HTTP feel raw" instinct belongs
    // to Route 2 (rendering / consumer-side reassembly + descriptor
    // MIME), which is NOT this route.
    let body = entity_ecf::ecf_for_hash(&entity.entity_type, &entity.data);
    // ETag uses the full 66-char wire-hash form (algorithm byte +
    // digest) per ruling §5 B — same encoding as the URL path and
    // the §6.4.2 binding leaf, so a consumer hitting `/content/{x}`
    // and reading the `ETag: "{y}"` finds `x == y`.
    let etag = format!("\"{}\"", hex_encode(&h.to_bytes()));
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/cbor")
        .header(
            hyper::header::CACHE_CONTROL,
            "immutable, max-age=31536000",
        )
        .header(hyper::header::ETAG, etag)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build failed".into(),
            )
        })
}

/// Parse a hex-encoded **33-byte wire hash** (66 chars: 1-byte
/// algorithm + 32-byte digest) into a [`Hash`]. Per ruling §5 B
/// the URL path component carries the full wire
/// representation, NOT the bare digest — so we can reject unknown
/// algorithm bytes here as 400 instead of silently coercing every
/// URL to SHA-256. V7 §3.5 + Hash::from_bytes() shape.
///
/// Returns a human-readable error message on bad length / bad chars
/// / unknown algorithm. The handler maps that into `400 malformed
/// hash` — same status whether it's length, charset, or algorithm,
/// so the route stays uniform.
fn parse_hex_hash(s: &str) -> Result<Hash, String> {
    if s.len() != 66 {
        return Err(format!(
            "expected 66 hex chars (1-byte algorithm + 32-byte digest, V7 §3.5), got {}",
            s.len()
        ));
    }
    let bytes = hex_decode(s).map_err(|e| format!("hex decode: {}", e))?;
    let h = Hash::from_bytes(&bytes).map_err(|e| format!("hash from bytes: {:?}", e))?;
    // V7 currently registers SHA-256 (0x00) only. The serving route
    // can't verify-by-rehash a hash it doesn't know how to recompute,
    // so reject unknown algorithms with the same 400 the cohort uses
    // (ruling §5 B regression-class guard).
    if h.algorithm != entity_hash::HASH_ALGORITHM_SHA256 {
        return Err(format!(
            "unknown hash algorithm 0x{:02x} (only SHA-256/0x00 is registered)",
            h.algorithm
        ));
    }
    Ok(h)
}

/// Encode bytes as lowercase hex. Workspace has no `hex` dep; this is
/// a 4-line replacement and is reused by the ETag builder + the
/// namespace-scope path builder.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Decode lowercase OR uppercase hex into bytes. Strict — any
/// non-hex char or odd length is an error. Length is caller-checked.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("non-hex character: {:?}", c as char)),
    }
}

/// Handle GET on the tree route: `/{peer_id}/{path}{suffix}` where
/// `{suffix}` is exactly one of `tree_leaf_suffix` (entity) or
/// `tree_listing_suffix` (listing). Called from [`route_poll`] after
/// the peer-id parse has already succeeded on the first segment.
///
/// `tail` is everything after the peer-id, starting with `/`. So for
/// URL `/<pid>/foo/bar.bin`, the router passes `tail = "/foo/bar.bin"`.
///
/// **Amendment 5 (§6.5.3.1).** Each URL is a concrete object key.
/// Append-one / strip-one bijection: the LAST segment carries the
/// suffix. Strip exactly one recognized suffix to recover the bound
/// path; entity vs listing chosen by suffix identity. A bare
/// last-segment with no recognized suffix ⇒ 404.
async fn handle_tree_get(
    pid: &entity_crypto::PeerId,
    tail: &str,
    shared: Arc<PeerShared>,
    routes: &Routes,
) -> Response<Full<Bytes>> {
    // Tail must start with `/` (we always call with leading `/` per
    // route_poll's `find('/')` split). Defensive: bare-tail ⇒ 404.
    if !tail.starts_with('/') || tail.len() < 2 {
        return not_found_opaque();
    }

    // §6.5.3.1 status table — reject `%2F` inside a path component.
    // The router gives us percent-decoded path bytes (hyper decodes
    // unreserved chars but preserves `%2F` because it's a delimiter
    // surrogate). We check for the literal `%2F` (or lowercase) in
    // the tail.
    if tail.contains("%2F") || tail.contains("%2f") {
        return text_response(
            StatusCode::BAD_REQUEST,
            "encoded slash (%2F) inside a path component is not permitted (§6.5.3.1 Amendment 5)"
                .to_string(),
        );
    }

    // Find the LAST segment to strip the suffix from.
    let (parent_part, last_seg) = match tail.rfind('/') {
        Some(i) => (&tail[..i + 1], &tail[i + 1..]),
        None => return not_found_opaque(),
    };
    if last_seg.is_empty() {
        // URL had a trailing slash (e.g. `/{pid}/foo/`). No trailing-
        // slash form per Amendment 5 ⇒ 404. (And no redirects.)
        return not_found_opaque();
    }

    let is_listing;
    let stem;
    if let Some(s) = last_seg.strip_suffix(&routes.tree_listing_suffix) {
        is_listing = true;
        stem = s;
    } else if let Some(s) = last_seg.strip_suffix(&routes.tree_leaf_suffix) {
        is_listing = false;
        stem = s;
    } else {
        // Bare path with no recognized suffix ⇒ 404 (§6.5.3.1).
        return not_found_opaque();
    }

    // Recover the tree-path (the binding key). For listings, the stem
    // may be empty when the URL is `/{pid}/foo/.list` — that's a
    // request to list `/{pid}/foo/`, not legal in our scheme (we serve
    // peer-root listing at `/{pid}.list`, not `/{pid}/.list`).
    // For a listing URL `/{pid}/foo/bar.list`, the listing target is
    // `/{pid}/foo/bar`. For an entity URL `/{pid}/foo/bar.bin`, the
    // binding is at `/{pid}/foo/bar`.
    let bound_path = format!("/{}{}{}", pid.as_str(), parent_part, stem);

    if is_listing {
        render_listing(&bound_path, shared, routes).await
    } else {
        // Entity branch: bound_path was the binding key.
        render_leaf(&bound_path, shared, routes).await
    }
}

/// Render the leaf response per §6.5.3.1 Amendment 6.
///
/// **Body shape (Amendment 6):** the bound hash as a
/// `system/hash` 2-key bare pointer — `ECF({type:"system/hash", data:H})`
/// — where `data` is the CBOR bstr of the 33-byte wire hash. The
/// consumer reads `H` from `data` and does a second-hop
/// `CONTENT_GET /content/{hex33(H)}` to fetch the entity bytes.
///
/// **Why two-hop, not one-hop (V7 §1.7 dedup invariant).** The
/// previous Amendment-5 reading inlined the dereferenced entity at
/// the path-addressed `.bin` URL. That violates V7 §1.7 — the
/// content store holds one copy per hash regardless of how many
/// paths bind to it. Inlining the entity at every `.bin` URL
/// materializes a separate copy per binding; a static CDN can't
/// dedup two `.bin` URLs that share bytes. Two-hop preserves the
/// `path → hash` and `hash → bytes` split: `.bin` answers the first
/// half; `/content/{hex33}` answers the second.
///
/// **Why 2-key not 3-key.** A path-addressed pointer has no useful
/// self-`content_hash` — its trust flows from the signed root
/// through the verified listing chain, not from its own hash. A
/// 3-key body would carry TWO hashes (bound `H` in `data` + the
/// pointer's own self-hash in `content_hash`) — footgun. Mirrors
/// `CONTENT_GET`'s 2-key bare precedent.
///
/// **No `Cache-Control: immutable`.** Bindings are mutable.
/// **ETag = the bound hash** (changes on rebind = correct mutable
/// cache key; NOT the pointer's self-hash — arch 0f60891
/// adversarial-review polish).
///
/// **No content_store lookup.** The pointer is built from the
/// binding alone; we don't dereference. If the consumer wants the
/// bytes, they do the second hop.
async fn render_leaf(
    abs_path: &str,
    shared: Arc<PeerShared>,
    routes: &Routes,
) -> Response<Full<Bytes>> {
    let scope = match &routes.scope {
        Some(s) => s,
        None => return not_found_opaque(),
    };

    // Tree-face scope check. Out-of-scope ⇒ identical 404 (T4).
    match scope.in_scope_path(abs_path, &shared).await {
        Ok(true) => {}
        Ok(false) => return not_found_opaque(),
        Err(e) => {
            tracing::warn!(error = %e, "http_live: tree-scope predicate errored");
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scope predicate error".to_string(),
            );
        }
    }

    let h = match shared.location_index.get(abs_path) {
        Some(h) => h,
        None => return not_found_opaque(),
    };

    // Build the 2-key bare pointer `ECF({type:"system/hash",
    // data:<CBOR bstr 33 bytes>})`. `ecf_for_hash_value` ECF-encodes
    // the data value first, then wraps in the {type, data} pair.
    let body = entity_ecf::ecf_for_hash_value(
        "system/hash",
        &entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
    );
    let etag = format!("\"{}\"", hex_encode(&h.to_bytes()));
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/cbor")
        .header(hyper::header::ETAG, etag)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build failed".into(),
            )
        })
}

/// Render a `system/tree/listing` wire entity for the children of
/// `abs_path` per §6.5.3.1 Amendment 5.
///
/// **Scope-gating (MUST; §6.5.6).** First confirm the listed prefix
/// itself is in scope (out-of-scope ⇒ identical 404 with not-held).
/// Then enumerate the immediate children of `abs_path` via the
/// LocationIndex and project each child through `in_scope_path` to
/// build the filtered set. `count` is the filtered total; an in-scope
/// prefix with no in-scope children returns 200 + entries={} +
/// count=0. `next_page` is omitted in v1 (single-page; pagination
/// chain is a follow-up).
///
/// **No `Cache-Control: immutable`**: listings are mutable views,
/// re-rendered on subtree change.
async fn render_listing(
    abs_path: &str,
    shared: Arc<PeerShared>,
    routes: &Routes,
) -> Response<Full<Bytes>> {
    let scope = match &routes.scope {
        Some(s) => s,
        None => return not_found_opaque(),
    };

    // Tree-face scope check on the listed prefix itself. Out-of-scope
    // ⇒ identical 404 (T4 presence-oracle — §6.5.6 listing rule).
    match scope.in_scope_path(abs_path, &shared).await {
        Ok(true) => {}
        Ok(false) => return not_found_opaque(),
        Err(e) => {
            tracing::warn!(error = %e, "http_live: tree-scope predicate errored");
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scope predicate error".to_string(),
            );
        }
    }

    // Build the enumeration prefix (LocationIndex::list uses a
    // textual prefix — we want children of `abs_path` so we need
    // `abs_path/`).
    let list_prefix = if abs_path.ends_with('/') {
        abs_path.to_string()
    } else {
        format!("{}/", abs_path)
    };
    let entries_raw = shared.location_index.list(&list_prefix);

    // Group raw bindings by their immediate child name, scope-filtered.
    use std::collections::BTreeMap;
    struct ChildInfo {
        hash: Option<Hash>,
        has_children: bool,
    }
    let mut children: BTreeMap<String, ChildInfo> = BTreeMap::new();
    for entry in &entries_raw {
        let rel = entry.path.strip_prefix(&list_prefix).unwrap_or(&entry.path);
        if rel.is_empty() {
            continue;
        }
        let (child_name, has_more) = match rel.find('/') {
            Some(i) => (&rel[..i], true),
            None => (rel, false),
        };
        // Scope-filter each candidate child path independently
        // (§6.5.6 — `count` MUST be the filtered total).
        let child_abs = format!("{}{}", list_prefix, child_name);
        match scope.in_scope_path(&child_abs, &shared).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "http_live: scope check failed on listing child");
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "scope predicate error".to_string(),
                );
            }
        }
        let info = children
            .entry(child_name.to_string())
            .or_insert(ChildInfo {
                hash: None,
                has_children: false,
            });
        if has_more {
            info.has_children = true;
        } else {
            info.hash = Some(entry.hash);
        }
    }

    let count = children.len();

    // Build the listing entity body. Field order is ECF key-encoded-
    // length then lex (matches core/tree::handle_listing).
    let entry_pairs: Vec<(entity_ecf::Value, entity_ecf::Value)> = children
        .iter()
        .map(|(name, info)| {
            let hash_val = match info.hash {
                Some(h) => entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                None => entity_ecf::Value::Null,
            };
            let entry_map = entity_ecf::Value::Map(vec![
                (entity_ecf::text("has_children"), entity_ecf::bool_val(info.has_children)),
                (entity_ecf::text("hash"), hash_val),
            ]);
            (entity_ecf::text(name), entry_map)
        })
        .collect();

    let listing_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("count"), entity_ecf::integer(count as i64)),
        (
            entity_ecf::text("entries"),
            entity_ecf::Value::Map(entry_pairs),
        ),
        (entity_ecf::text("offset"), entity_ecf::integer(0)),
        (entity_ecf::text("path"), entity_ecf::text(abs_path)),
        // `next_page` omitted in v1 (single-page); the field is
        // optional per V7 §3.9 (Amendment 5) so absent ⇒ last page.
    ]));

    let listing_entity = match entity_entity::Entity::new(
        entity_types::TYPE_TREE_LISTING,
        listing_data,
    ) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "http_live: failed to build listing entity");
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "listing build failed".into(),
            );
        }
    };

    // Wire entity (3-key) per §6.5.3.1. NO Cache-Control immutable —
    // listings are mutable views.
    let body = entity_wire::encode_entity(&listing_entity);
    let etag = format!("\"{}\"", hex_encode(&listing_entity.content_hash.to_bytes()));
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/cbor")
        .header(hyper::header::ETAG, etag)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build failed".into(),
            )
        })
}

/// Handle `GET /{peer_id}{tree_listing_suffix}` per §6.5.3 — the
/// peer-root listing. Equivalent to listing the children of
/// `/{peer_id}`.
async fn handle_peer_root_listing(
    pid: &entity_crypto::PeerId,
    shared: Arc<PeerShared>,
    routes: &Routes,
) -> Response<Full<Bytes>> {
    let abs_path = format!("/{}", pid.as_str());
    render_listing(&abs_path, shared, routes).await
}

/// Handle `GET /peers{tree_listing_suffix}` per §6.5.3 — the all-peers
/// (universal-tree-root) listing. The set of peer-ids whose subtree
/// resolves under the current `serve_scope`. Implemented as a
/// listing of the root `/` whose immediate children are peer-ids.
async fn handle_all_peers_listing(
    shared: Arc<PeerShared>,
    routes: &Routes,
) -> Response<Full<Bytes>> {
    render_listing("/", shared, routes).await
}

/// Handle `GET {manifest_prefix}` per §6.5.3.1 Amendment 5.
///
/// **Body (MUST).** The publisher's signed manifest as a wire entity
/// `ECF({type, data, content_hash})`, `Content-Type: application/cbor`.
/// **Singular / terminal:** no suffix, no trailing slash; any
/// `/manifest/...` form is matched in [`route_poll`] only by the
/// exact literal `/manifest` (no path tail) — anything else falls
/// through to 404.
///
/// **Cache (MUST NOT be immutable).** The manifest is mutable
/// (revocation lives there per PROPOSAL-PEER-MANIFEST-STATIC-
/// HANDSHAKE); a short `max-age` is used so a CDN can cache briefly
/// but revocation propagates.
async fn handle_manifest_get(
    shared: Arc<PeerShared>,
    routes: &Routes,
) -> Response<Full<Bytes>> {
    // Prefer an explicitly-configured static manifest hash; otherwise serve the
    // current published-root head pointer (Phase P — dynamic re-publishing keeps
    // MANIFEST_GET fresh as the tree root changes). PROPOSAL-PEER-MANIFEST §4.
    let h = match routes.manifest_hash {
        Some(h) => h,
        None => match shared
            .location_index
            .get(&crate::published_root::published_root_head_path(
                shared.peer_id.as_str(),
            )) {
            Some(h) => h,
            None => return not_found_opaque(),
        },
    };
    let entity = match shared.content_store.get(&h) {
        Some(e) => e,
        None => return not_found_opaque(),
    };

    let body = entity_wire::encode_entity(&entity);
    let etag = format!("\"{}\"", hex_encode(&h.to_bytes()));
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/cbor")
        // Mutable — MUST NOT be `immutable`. Short max-age supports
        // CDN caching with bounded revocation latency.
        .header(hyper::header::CACHE_CONTROL, "max-age=60")
        .header(hyper::header::ETAG, etag)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build failed".into(),
            )
        })
}

/// Build the canonical "not found" response used for the
/// out-of-scope + not-held cases. Identical body — T4 mitigation per
/// arch ruling §1.3 (no presence oracle).
fn not_found_opaque() -> Response<Full<Bytes>> {
    text_response(StatusCode::NOT_FOUND, "not found".to_string())
}

/// Build a 405 Method Not Allowed response with the `Allow` header.
fn method_not_allowed(actual: Method, allow: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(hyper::header::ALLOW, allow)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(format!(
            "method {} not allowed; this endpoint accepts {} only",
            actual, allow
        ))))
        .expect("static 405 response build")
}

/// Build a plain-text error response. Used for transport-layer errors
/// (bad path, bad method, body-read failure, malformed envelope) —
/// **never** for entity-protocol errors, which travel inside an
/// EXECUTE-RESPONSE envelope body with 200 OK at the HTTP layer
/// (entity-protocol owns its own status codes).
fn text_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("static text response build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_route_path_adds_leading_slash() {
        assert_eq!(normalize_route_path("entity".to_string()), "/entity");
        assert_eq!(normalize_route_path("/entity".to_string()), "/entity");
        assert_eq!(normalize_route_path("/entity/".to_string()), "/entity");
        assert_eq!(normalize_route_path("/".to_string()), "/");
    }

    #[test]
    fn normalize_prefix_preserves_empty() {
        assert_eq!(normalize_prefix(String::new()), "");
        assert_eq!(normalize_prefix("/poll".to_string()), "/poll");
        assert_eq!(normalize_prefix("poll".to_string()), "/poll");
        assert_eq!(normalize_prefix("/poll/".to_string()), "/poll");
    }

    #[test]
    fn strip_prefix_with_boundary_matches_prefix_or_slash() {
        assert_eq!(strip_prefix_with_boundary("/poll", "/poll"), Some(""));
        assert_eq!(
            strip_prefix_with_boundary("/poll/content/abc", "/poll"),
            Some("/content/abc")
        );
        // A path that merely starts with the prefix as a substring is
        // NOT a match — `/poller/foo` is its own path, not nested
        // under `/poll`.
        assert_eq!(strip_prefix_with_boundary("/poller/foo", "/poll"), None);
        // Empty prefix matches everything (Posture 1 mount-at-root).
        assert_eq!(
            strip_prefix_with_boundary("/content/abc", ""),
            Some("/content/abc")
        );
    }

    #[test]
    fn parse_hex_hash_validates_length_charset_and_algorithm() {
        // Canonical 66-char SHA-256 wire form: 0x00 || digest.
        let mut wire = [0u8; 33];
        wire[0] = 0x00;
        for b in wire[1..].iter_mut() {
            *b = 0xAB;
        }
        let hex = hex_encode(&wire);
        assert_eq!(hex.len(), 66);
        let h = parse_hex_hash(&hex).expect("66-char SHA-256 wire parses");
        assert_eq!(h.algorithm, 0x00);
        assert_eq!(h.digest(), [0xAB; 32]);

        // §5 B regression guard — 64 hex chars (digest only) MUST be
        // rejected so cohort fallback to the pre-ruling form is loud.
        let bare_digest_hex = hex_encode(&[0xAB; 32]);
        assert_eq!(bare_digest_hex.len(), 64);
        assert!(parse_hex_hash(&bare_digest_hex).is_err());

        // Bad length.
        assert!(parse_hex_hash("short").is_err());

        // Bad charset at right length.
        assert!(parse_hex_hash(&"zz".repeat(33)).is_err());

        // Unknown algorithm byte (V7 currently defines only 0x00) —
        // Hash::from_bytes rejects.
        let mut unknown_algo = [0u8; 33];
        unknown_algo[0] = 0xFE;
        let unknown_hex = hex_encode(&unknown_algo);
        let result = parse_hex_hash(&unknown_hex);
        assert!(
            result.is_err(),
            "unknown algorithm byte must error, got {:?}",
            result
        );
    }

    #[test]
    fn hex_encode_decode_round_trip() {
        let bytes = (0u8..=255).collect::<Vec<u8>>();
        let s = hex_encode(&bytes);
        assert_eq!(s.len(), 512);
        let back = hex_decode(&s).expect("decode round-trip");
        assert_eq!(back, bytes);
        // Mixed case accepted on decode.
        assert_eq!(hex_decode("aBcD").unwrap(), vec![0xab, 0xcd]);
        // Odd length rejected.
        assert!(hex_decode("abc").is_err());
        // Non-hex rejected.
        assert!(hex_decode("zz").is_err());
    }
}
