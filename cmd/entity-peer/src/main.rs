mod commands;
mod config;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "entity", about = "Entity Core Protocol peer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage identity keypairs
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Manage peers
    Peer {
        /// Verbose output (debug logging)
        #[arg(short, long)]
        verbose: bool,
        /// Trace entity encode/decode and storage
        #[arg(long)]
        trace_entities: bool,
        /// Print span enter/close events with time.busy / time.idle for
        /// instrumented functions (handle_connection, dispatch_request,
        /// verify_request, read_frame, write_frame, dispatch_event,
        /// per-sync-hook). Implies a debug-level filter that includes the
        /// instrumented crates.
        #[arg(long)]
        profile: bool,
        #[command(subcommand)]
        action: PeerAction,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Create a new identity keypair
    Create {
        /// Name for the identity (default: "default")
        #[arg(default_value = "default")]
        name: String,
        /// Signature key type (v7.67): ed25519 (default) or ed448
        #[arg(long, default_value = "ed25519")]
        key_type: String,
    },
    /// List all identities
    List,
    /// Show identity details
    Show {
        /// Identity name
        #[arg(default_value = "default")]
        name: String,
    },
}

#[derive(Subcommand)]
enum PeerAction {
    /// Initialize a new peer
    Init {
        /// Peer name
        name: String,
        /// Admin identity name
        #[arg(long)]
        admin: Option<String>,
        /// Admin peer ID (external)
        #[arg(long = "admin-key")]
        admin_key: Option<String>,
        /// Signature key type (v7.67): ed25519 (default) or ed448. The
        /// minted keypair is saved with an algorithm-tagged PEM header;
        /// `peer start` auto-detects the type from that header.
        #[arg(long, default_value = "ed25519")]
        key_type: String,
    },
    /// Start a peer
    Start {
        /// Peer name
        name: String,
        /// TCP listen address (overrides config)
        #[arg(short, long)]
        listen: Option<String>,
        /// WebSocket listen address (e.g., 0.0.0.0:4041)
        #[arg(long)]
        ws_listen: Option<String>,
        /// HTTP-live listen address (e.g., 0.0.0.0:4080). Enables the
        /// `system/peer/transport/http` profile per EXTENSION-NETWORK
        /// §6.5.2c. Accepts POST EXECUTE → EXECUTE-RESPONSE per
        /// Amendment 3 (bare ECF body, Content-Length-framed). Matches
        /// Go peer's `-http-addr` flag for cross-impl interop.
        #[arg(long)]
        http_listen: Option<String>,
        /// HTTP-live URL path (default /entity). Operator choice per G1;
        /// the published profile's `endpoint.url` MUST advertise this
        /// path. Matches Go peer's `-http-path` flag.
        #[arg(long, default_value = "/entity")]
        http_path: String,
        /// HTTP-poll (serving-mode) listen address (e.g., 0.0.0.0:9201).
        /// Enables the `system/peer/transport/http-poll` profile per the
        /// serving-mode content-scope ruling
        /// (Posture 1, RECOMMENDED — isolated port for serving).
        /// Mutually exclusive with --http-poll-mount-on-live.
        /// Matches Go peer's `-http-poll-addr` flag.
        #[arg(long, conflicts_with = "http_poll_mount_on_live")]
        http_poll_addr: Option<String>,
        /// Mount the http-poll serving routes on the existing
        /// --http-listen listener (Posture 2 — same port for live +
        /// serving). Required when 80/443 must be reused. Mutually
        /// exclusive with --http-poll-addr.
        #[arg(long, conflicts_with = "http_poll_addr")]
        http_poll_mount_on_live: bool,
        /// Path prefix for poll routes when mounted on the live
        /// listener. Default `/poll`. Ignored unless
        /// --http-poll-mount-on-live is set. G4 advisory: operator
        /// MUST pick a non-colliding live --http-path.
        #[arg(long, default_value = "/poll")]
        http_poll_prefix: String,
        /// Content-namespace scope for the poll listener (RECOMMENDED
        /// default per ruling §1.2). Format: `system/content/<ns>`
        /// (e.g., `system/content/public`). The route serves H iff
        /// `/<peer_id>/<namespace>/{hex(H)}` is bound in the tree.
        /// Required when http-poll is enabled (no scope = no serving;
        /// closure-scope + whole-store opt-in land in E.3.x).
        #[arg(long)]
        serve_namespace: Option<String>,
        /// Closure-of-signed-root serving scope (NETWORK §6.5.6
        /// Amendment 10). The poll route serves the transitive trie-node
        /// closure reachable from `published-root.root_hash` (root node,
        /// interior sub-nodes, leaf-bound values, the published-root
        /// entity + its signature) — the floor that lets a consumer walk
        /// a signed root. Mutually exclusive with --serve-namespace; pair
        /// with --publish-root, which then publishes over the whole peer
        /// subtree. Matches Go peer's `--serve-closure-root`.
        #[arg(long, conflicts_with = "serve_namespace")]
        serve_closure_root: bool,
        /// Storage backend: "memory" or "sqlite" (overrides config.toml)
        #[arg(long)]
        storage: Option<String>,
        /// Issue wide-open grants on connection (debug only)
        #[arg(long)]
        debug_grants: bool,
        /// Enable history recording (format: pattern[:max_depth], e.g. "*" or "*:1000" or "project/*")
        #[arg(long)]
        history: Option<String>,
        /// Expose a filesystem directory via the local/files handler.
        /// Format: name:/fs/path:tree/prefix/ (matches Go peer's --files).
        #[arg(long)]
        files: Option<String>,
        /// Home `content_hash_format` this peer authors under and prefers
        /// in hello negotiation (V7 §4.5/§8.2): "sha256" (default, the
        /// conformance floor) or "sha384". The per-connection active format
        /// is negotiated and may differ (a sha384 peer authors sha256 on a
        /// connection to a sha256-only peer). Matches Go peer's
        /// `--hash-type` flag.
        #[arg(long, default_value = "sha256")]
        hash_type: String,
        /// Enable GUIDE-CONFORMANCE §7a test handlers (system/validate/echo +
        /// system/validate/dispatch-outbound) for validate-peer probing. OFF
        /// by default — these expose §6.13(a)/§6.13(b) for black-box wire
        /// attestation and MUST NOT be on in production (dispatch-outbound
        /// originates outbound EXECUTEs from caller params). A default peer
        /// 404s system/validate/* so the validator SKIPs honestly per §7a.4.
        #[arg(long)]
        validate: bool,
        /// Phase P: on startup, author + sign a `system/peer/published-root`
        /// over the `--serve-namespace` subtree so `MANIFEST_GET` serves a
        /// signed tree root (PROPOSAL-PEER-MANIFEST §4). Requires
        /// `--serve-namespace`. Static one-time publish (coral-reef publisher);
        /// re-publish-on-change is a documented follow-up.
        #[arg(long)]
        publish_root: bool,
        /// Enable EXTENSION-CONTENT v3.5 §5.3 descriptor publication on
        /// `--files` roots (DOMAIN-LOCAL-FILES §2.5). With this set, a
        /// `read` of a file with a known media-type publishes a
        /// `system/content/descriptor` at the canonical
        /// `/{peer}/system/content/descriptor/{B_hex}/{D_hex}` path.
        /// Sets `RootConfigData.publish_descriptors` on the configured
        /// root. Matches Go peer's `--publish-descriptors`.
        #[arg(long)]
        publish_descriptors: bool,
    },
    /// List all peers
    List,
    /// Show peer details
    Show {
        /// Peer name
        name: String,
    },
    /// Issue a curated peer-issued registry binding (operator tool, holds the
    /// registry key = this peer's identity). Signs a `name → target_peer_id`
    /// binding with the peer's key and publishes the body + signature + by-name
    /// pointer into the peer's tree, ready to be served as a coral-reef
    /// (PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §3.2). Resolvers that pin this
    /// peer's key resolve the name through the `peer-issued` backend.
    IssueBinding {
        /// Registry peer name (its identity is the signing key K_registry)
        name: String,
        /// The name to bind (e.g. billslab.com; NFC, no '/', no control chars)
        bind_name: String,
        /// Target peer-id the name resolves to (Base58, V7 §1.5)
        target_peer_id: String,
        /// Dial-able transport endpoint (repeatable), e.g. tcp://billslab.com:9000
        #[arg(long = "transport")]
        transports: Vec<String>,
        /// Time-to-live in milliseconds (omit for no expiry)
        #[arg(long)]
        ttl_ms: Option<u64>,
        /// Storage backend: "memory" or "sqlite" (overrides config.toml).
        /// Use "sqlite" so the binding persists for `peer start` to serve.
        #[arg(long)]
        storage: Option<String>,
        /// Home content_hash_format ("sha256" default or "sha384") — MUST match
        /// what `peer start` serves this registry under.
        #[arg(long, default_value = "sha256")]
        hash_type: String,
    },
}

fn init_tracing(verbose: bool, trace_entities: bool, profile: bool) {
    // Default filter. --profile enables span events on the instrumented crates
    // at debug, which is what surfaces time.busy / time.idle on each span close.
    let default_filter = if trace_entities {
        "trace".to_string()
    } else if profile {
        // Quiet at info, but the instrumented crates at debug so spans fire.
        "info,entity_peer=debug,entity_protocol=debug,entity_wire=debug,entity_store=debug"
            .to_string()
    } else if verbose {
        "debug".to_string()
    } else {
        "info".to_string()
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| default_filter.into());

    let builder = tracing_subscriber::fmt().with_env_filter(env_filter);

    if profile {
        // FmtSpan::CLOSE prints "<span>: close time.busy=<x> time.idle=<y>"
        // when each instrumented span ends. CPU time vs await time, no extra
        // deps, viewable in any tail-able log.
        builder
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .init();
    } else {
        builder.init();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Identity { action } => {
            init_tracing(false, false, false);
            match action {
                IdentityAction::Create { name, key_type } => {
                    commands::identity::create(&name, &key_type)?
                }
                IdentityAction::List => commands::identity::list()?,
                IdentityAction::Show { name } => commands::identity::show(&name)?,
            }
        }
        Commands::Peer {
            verbose,
            trace_entities,
            profile,
            action,
        } => {
            init_tracing(verbose, trace_entities, profile);
            match action {
                PeerAction::Init {
                    name,
                    admin,
                    admin_key,
                    key_type,
                } => commands::peer::init(
                    &name,
                    admin.as_deref(),
                    admin_key.as_deref(),
                    &key_type,
                )?,
                PeerAction::Start {
                    name,
                    listen,
                    ws_listen,
                    http_listen,
                    http_path,
                    http_poll_addr,
                    http_poll_mount_on_live,
                    http_poll_prefix,
                    serve_namespace,
                    serve_closure_root,
                    storage,
                    debug_grants,
                    history,
                    files,
                    hash_type,
                    validate,
                    publish_root,
                    publish_descriptors,
                } => {
                    commands::peer::start(
                        &name,
                        listen.as_deref(),
                        ws_listen.as_deref(),
                        http_listen.as_deref(),
                        &http_path,
                        http_poll_addr.as_deref(),
                        http_poll_mount_on_live,
                        &http_poll_prefix,
                        serve_namespace.as_deref(),
                        serve_closure_root,
                        storage.as_deref(),
                        debug_grants,
                        history.as_deref(),
                        files.as_deref(),
                        &hash_type,
                        validate,
                        publish_root,
                        publish_descriptors,
                    )
                    .await?
                }
                PeerAction::List => commands::peer::list_peers()?,
                PeerAction::Show { name } => commands::peer::show(&name)?,
                PeerAction::IssueBinding {
                    name,
                    bind_name,
                    target_peer_id,
                    transports,
                    ttl_ms,
                    storage,
                    hash_type,
                } => commands::peer::issue_binding(
                    &name,
                    &bind_name,
                    &target_peer_id,
                    &transports,
                    ttl_ms,
                    storage.as_deref(),
                    &hash_type,
                )?,
            }
        }
    }

    Ok(())
}
