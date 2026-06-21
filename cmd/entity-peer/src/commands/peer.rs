//! peer init/start/list/show commands.

use std::fs;

use entity_core::crypto::IdentityKeypair;
use entity_core::peer::transport::Listener;
use entity_core::peer::{PeerBuilder, PeerConfig};

use crate::config;

/// Initialize a new peer.
pub fn init(
    name: &str,
    _admin: Option<&str>,
    _admin_key: Option<&str>,
    key_type: &str,
) -> anyhow::Result<()> {
    let dir = config::peer_dir(name);
    if dir.exists() {
        anyhow::bail!("peer '{}' already exists at {}", name, dir.display());
    }
    fs::create_dir_all(&dir)?;

    // Generate peer keypair of the requested key_type (v7.67 Phase 2).
    // Saved with an algorithm-tagged PEM header so `start` auto-detects it.
    let kp = crate::commands::mint_identity(key_type)?;
    let key_path = dir.join("keypair");
    kp.save_to_file(&key_path)?;

    // Write config.toml (compatible with old Rust impl format)
    let peer_config = config::PeerToml::default();
    let config_toml = toml::to_string_pretty(&peer_config)?;
    fs::write(dir.join("config.toml"), config_toml)?;

    // Write grants.toml
    let grants = config::GrantsToml::default();
    let grants_toml = toml::to_string_pretty(&grants)?;
    fs::write(dir.join("grants.toml"), grants_toml)?;

    println!("initialized peer '{}'", name);
    println!("  dir:      {}", dir.display());
    println!("  key_type: {}", kp.key_type().label());
    println!("  peer_id:  {}", kp.peer_id());
    println!("  config:   {}", dir.join("config.toml").display());
    println!("  grants:   {}", dir.join("grants.toml").display());

    Ok(())
}

/// Load peer config, tolerating old-format fields.
fn load_peer_config(name: &str) -> anyhow::Result<config::PeerToml> {
    let dir = config::peer_dir(name);
    let config_path = dir.join("config.toml");
    let config_str = fs::read_to_string(&config_path)?;
    let peer_toml: config::PeerToml = toml::from_str(&config_str)?;
    Ok(peer_toml)
}

/// Start a peer.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    name: &str,
    listen_addr: Option<&str>,
    ws_listen_addr: Option<&str>,
    http_listen_addr: Option<&str>,
    http_url_path: &str,
    http_poll_addr: Option<&str>,
    http_poll_mount_on_live: bool,
    http_poll_prefix: &str,
    serve_namespace: Option<&str>,
    serve_closure_root: bool,
    storage_override: Option<&str>,
    debug_grants: bool,
    history_flag: Option<&str>,
    files_flag: Option<&str>,
    hash_type: &str,
    validate: bool,
    publish_root: bool,
    publish_descriptors: bool,
) -> anyhow::Result<()> {
    // A serving scope is either a content namespace or closure-of-signed-root
    // (NETWORK §6.5.6 Amendment 10). Exactly one may be selected (clap enforces
    // mutual exclusivity of the flags).
    let scope_selected = serve_namespace.is_some() || serve_closure_root;
    if publish_root && !scope_selected {
        anyhow::bail!(
            "--publish-root requires --serve-namespace or --serve-closure-root \
             (the subtree to publish a signed root over: a content namespace, \
             or the whole peer subtree under --serve-closure-root)"
        );
    }
    // Fail-fast validation of the http-poll surface (mirrors Go's
    // startup-rule discipline so cohort interop tracks at the surface).
    let poll_enabled = http_poll_addr.is_some() || http_poll_mount_on_live;
    if http_poll_mount_on_live && http_listen_addr.is_none() {
        anyhow::bail!(
            "--http-poll-mount-on-live requires --http-listen \
             (there's no live listener to mount onto)"
        );
    }
    if poll_enabled && !scope_selected {
        anyhow::bail!(
            "--http-poll-addr / --http-poll-mount-on-live requires a serving \
             scope: --serve-namespace (content-namespace) or \
             --serve-closure-root (closure-of-signed-root, NETWORK §6.5.6 \
             Amendment 10)"
        );
    }
    if !poll_enabled && scope_selected {
        anyhow::bail!(
            "--serve-namespace / --serve-closure-root requires --http-poll-addr \
             or --http-poll-mount-on-live"
        );
    }
    if publish_descriptors && files_flag.is_none() {
        // The flag only gates descriptor publication on `--files` roots
        // (DOMAIN-LOCAL-FILES §2.5). Without a root it has no effect —
        // surface the misconfiguration rather than failing silently.
        tracing::warn!(
            "--publish-descriptors has no effect without --files \
             (it gates descriptor publication on a local-files root)"
        );
    }
    let dir = config::peer_dir(name);
    if !dir.exists() {
        anyhow::bail!(
            "peer '{}' not found. Run `entity peer init {}` first",
            name,
            name
        );
    }

    // Load keypair — header-dispatched so Ed25519 and Ed448 identity files
    // both load (v7.67 Phase 2). Existing untagged files load as Ed25519.
    let key_path = dir.join("keypair");
    let keypair = IdentityKeypair::load_from_file(&key_path)?;
    let peer_id = keypair.peer_id();

    // Load config
    let peer_toml = load_peer_config(name)?;

    let addr = listen_addr.unwrap_or(&peer_toml.peer.listen_addr);

    // V7 §4.5/§8.2: map the CLI hash-type label to its content_hash_format
    // code. This is the peer's home/preferred format; the per-connection
    // active format is negotiated.
    let home_hash_format = match hash_type {
        "sha256" | "ecfv1-sha256" => entity_core::hash::HASH_ALGORITHM_SHA256,
        "sha384" | "ecfv1-sha384" => entity_core::hash::HASH_ALGORITHM_SHA384,
        other => anyhow::bail!(
            "unsupported --hash-type {:?} (expected \"sha256\" or \"sha384\")",
            other
        ),
    };

    // V7 §1.2 / v7.70: this peer authors its persistent content and substrate
    // (stored entities, trie nodes, revision entries, handler results,
    // locally-minted caps, its own identity entity, the format-relative
    // deletion marker) under its home format — not SHA-256 content with a
    // SHA-384 wire advertisement (the pre-v7.70 incoherence). The CLI runs one
    // peer per process, so setting the process home default here (before the
    // peer is built and any home authoring happens) is the deployment entry
    // point for that choice. Connection authoring under a negotiated active
    // format (§4.5a) keeps using the explicit `*_with_format` paths.
    entity_core::hash::set_default_hash_format(home_hash_format);

    let peer_config = PeerConfig {
        listen_addr: addr.to_string(),
        max_connections: peer_toml.peer.max_connections.unwrap_or(100),
        connection_timeout_secs: peer_toml.peer.connection_timeout_secs.unwrap_or(30),
        debug_open_grants: debug_grants,
        home_hash_format,
        ..PeerConfig::default()
    };

    let mut builder = PeerBuilder::new()
        .identity_keypair(keypair)
        .config(peer_config);

    // GUIDE-CONFORMANCE §7a opt-in (--validate). Registers the
    // system/validate/* wire-gate handlers so validate-peer can black-box
    // probe §6.13(a)/(b). OFF by default; MUST NOT be on in production.
    if validate {
        builder = builder.with_conformance_handlers();
    }

    // Configure storage backend: CLI --storage flag overrides config.toml
    let storage_backend = storage_override
        .map(|s| s.to_string())
        .or_else(|| peer_toml.storage.as_ref().map(|s| s.backend.clone()))
        .unwrap_or_else(|| "memory".to_string());

    let storage_path;
    #[cfg(feature = "sqlite")]
    if storage_backend == "sqlite" {
        let db_file = peer_toml
            .storage
            .as_ref()
            .and_then(|s| s.path.as_deref())
            .unwrap_or("store.db");
        storage_path = dir.join(db_file);
        builder = builder.sqlite(&storage_path)?;
    }
    #[cfg(not(feature = "sqlite"))]
    if storage_backend == "sqlite" {
        anyhow::bail!("sqlite storage requires the 'sqlite' feature (not compiled in)");
    }

    let peer = builder.build()?;

    // --history flag: store a history config entity so the engine records transitions
    if let Some(history_spec) = history_flag {
        let (pattern, max_depth) = parse_history_flag(history_spec)?;
        let pid = peer.peer_id().to_string();

        let mut fields = vec![
            (entity_core::ecf::text("pattern"), entity_core::ecf::text(&pattern)),
            (entity_core::ecf::text("enabled"), entity_core::ecf::bool_val(true)),
            (
                entity_core::ecf::text("events"),
                entity_core::ecf::Value::Array(vec![
                    entity_core::ecf::text("created"),
                    entity_core::ecf::text("updated"),
                    entity_core::ecf::text("deleted"),
                ]),
            ),
        ];
        if let Some(depth) = max_depth {
            fields.push((
                entity_core::ecf::text("max_depth"),
                entity_core::ecf::integer(depth as i64),
            ));
        }
        let data = entity_core::ecf::to_ecf(&entity_core::ecf::Value::Map(fields));
        let config_entity = entity_core::entity::Entity::new(
            entity_core::types::TYPE_HISTORY_CONFIG,
            data,
        )?;
        let config_hash = peer.content_store().put(config_entity)?;
        peer.location_index().set(
            &format!("/{}/system/history/config/cli", pid),
            config_hash,
        );
        println!("  history: enabled for pattern {:?}{}", pattern,
            max_depth.map(|d| format!(" (max_depth: {})", d)).unwrap_or_default());
    }

    // --files: register a root mapping for the local/files handler. Matches
    // the Go peer's `--files name:/fs/path:tree/prefix/` flag so the
    // cross-impl validate-peer suite can target a configured root.
    if let Some(spec) = files_flag {
        let (root_name, fs_path, prefix) = parse_files_flag(spec)?;
        let cfg = entity_core::peer::local_files::RootConfigData {
            prefix: prefix.clone(),
            filesystem_root: fs_path.clone(),
            publish_descriptors,
            ..Default::default()
        };
        peer.local_files_handler().add_root(&root_name, cfg)
            .map_err(|e| anyhow::anyhow!("add files root: {e}"))?;
        println!(
            "  files:   {} → {} (tree prefix: {}{})",
            root_name,
            fs_path,
            prefix,
            if publish_descriptors { ", descriptors" } else { "" }
        );
    }

    let tcp_listener = peer.listen().await?;
    let tcp_addr = tcp_listener.socket_addr();

    println!("peer '{}' started", name);
    println!("  peer_id: {}", peer_id);
    println!("  storage: {}", storage_backend);
    println!("  tcp:     {}", tcp_addr);

    // Self-publish the local TCP transport profile (EXTENSION-NETWORK
    // §6.5.2a / transport-family R3). A peer that doesn't advertise a
    // reachable profile can't be dialed by hash-resolution, and
    // `transport_family.r3_profile_enum_membership` checks the §6.5.1 enum
    // fields are populated. Bound at
    // `/{pid}/system/peer/transport/{own_identity_hex}/primary` — the same
    // path the dialer resolves a remote's profile from.
    if let Err(e) = publish_self_tcp_profile(&peer, tcp_addr) {
        tracing::error!("self-publish TCP transport profile failed: {}", e);
    }

    // Build listener list: always TCP, optionally WebSocket
    let mut listeners: Vec<Box<dyn Listener>> = vec![Box::new(tcp_listener)];

    if let Some(ws_addr) = ws_listen_addr {
        let ws_listener = entity_core::peer::transport::WebSocketListener::bind(ws_addr).await?;
        println!("  ws:      ws://{}", ws_listener.socket_addr());
        listeners.push(Box::new(ws_listener));
    }

    // Phase P: author + sign a published-root over the served subtree so
    // MANIFEST_GET serves a signed tree root (PROPOSAL-PEER-MANIFEST §4). The
    // trie is keyed by peer-prefix-stripped paths (the root_tracker convention;
    // cross-impl key reconciliation is a validate-peer item — see
    // docs/SPEC-AMBIGUITIES.md). Static one-time publish; an empty subtree
    // still publishes the canonical empty CHAMP root (a real served node) so
    // MANIFEST_GET / the trie-closure GET resolve regardless of content.
    if publish_root {
        // --serve-namespace scopes the published subtree; --serve-closure-root
        // publishes over the whole peer subtree (the closure floor a consumer
        // walks). serve_namespace and serve_closure_root are mutually exclusive.
        match publish_served_root(&peer, serve_namespace) {
            Ok((head, seq)) => println!(
                "  published-root: seq={} head={} (serving {})",
                seq,
                head.to_hex(),
                serve_namespace.unwrap_or("<whole peer subtree>")
            ),
            Err(e) => tracing::error!("publish-root failed: {}", e),
        }
    }

    // Serving scope. When --publish-root advertises a signed_pointer, the floor
    // is closure-of-signed-root (NETWORK §6.5.6 Amendment 10): the served set
    // MUST cover the trie-node closure reachable from the published root so a
    // consumer's PEER-MANIFEST §1.1 walk-from-signed-root can CONTENT_GET every
    // interior node (hash-linked, not path-bound — V7 §1.7) + resolve the
    // signature pointer. Otherwise a content-only mirror serves the configured
    // content namespace (path-bound). The same Arc is shared by both postures.
    let scope: Option<std::sync::Arc<dyn entity_core::peer::http_live::ScopePredicate>> =
        if publish_root || serve_closure_root {
            Some(std::sync::Arc::new(entity_core::peer::http_live::ClosureScope::new())
                as std::sync::Arc<dyn entity_core::peer::http_live::ScopePredicate>)
        } else {
            serve_namespace.map(|ns| {
                std::sync::Arc::new(entity_core::peer::http_live::NamespaceScope::new(ns))
                    as std::sync::Arc<dyn entity_core::peer::http_live::ScopePredicate>
            })
        };

    // HTTP-live listener (EXTENSION-NETWORK §6.5.2c). Optional; binds
    // alongside TCP/WS when --http-listen is given. The HTTP transport
    // doesn't fit the stream-oriented Listener trait (request/response
    // not duplex stream), so it runs in its own serve loop rather than
    // joining the run_multi listener vec.
    //
    // Posture 2: when --http-poll-mount-on-live is set, this same
    // listener also serves the http-poll routes under --http-poll-prefix.
    let http_handle = if let Some(http_addr) = http_listen_addr {
        let mut http_listener =
            entity_core::peer::http_live::HttpLiveListener::bind(http_addr, http_url_path)
                .await?;
        if http_poll_mount_on_live {
            http_listener = http_listener.with_poll_prefix(http_poll_prefix);
            if let Some(s) = scope.clone() {
                http_listener = http_listener.with_scope(s);
            }
        }
        let bound = http_listener.bound_addr();
        let bound_path = http_listener
            .url_path()
            .expect("live listener has execute path")
            .to_string();
        println!("  http:    http://{}{}", bound, bound_path);
        if http_poll_mount_on_live {
            println!(
                "  http-poll (mounted): http://{}{}/{{content,tree}}/...",
                bound,
                http_listener.poll_prefix().unwrap_or("")
            );
        }
        let shared = peer.shared();
        Some(tokio::spawn(async move {
            if let Err(e) = http_listener.serve(shared).await {
                tracing::error!("http-live listener stopped with error: {}", e);
            }
        }))
    } else {
        None
    };

    // HTTP-poll isolated-port listener (Posture 1). Lit when
    // --http-poll-addr is set. Mutually exclusive with
    // --http-poll-mount-on-live (clap-enforced + start-side checked).
    let http_poll_handle = if let Some(addr) = http_poll_addr {
        let mut poll_listener =
            entity_core::peer::http_live::HttpLiveListener::bind_poll(addr, "")
                .await?;
        if let Some(s) = scope.clone() {
            poll_listener = poll_listener.with_scope(s);
        }
        let bound = poll_listener.bound_addr();
        println!(
            "  http-poll: http://{}/{{content,tree}}/... (scope: {})",
            bound,
            scope.as_ref().map(|s| s.describe()).unwrap_or_else(|| "(none)".to_string()),
        );
        let shared = peer.shared();
        Some(tokio::spawn(async move {
            if let Err(e) = poll_listener.serve(shared).await {
                tracing::error!("http-poll listener stopped with error: {}", e);
            }
        }))
    } else {
        None
    };

    // Run until ctrl-c
    tokio::select! {
        result = peer.run_multi(listeners) => {
            if let Err(e) = result {
                tracing::error!("peer stopped with error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nshutting down...");
        }
    }

    if let Some(handle) = http_handle {
        handle.abort();
    }
    if let Some(handle) = http_poll_handle {
        handle.abort();
    }

    Ok(())
}

/// List all configured peers.
pub fn list_peers() -> anyhow::Result<()> {
    let dir = config::peers_dir();
    if !dir.exists() {
        println!("no peers found");
        return Ok(());
    }

    let mut found = false;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let name = entry
            .file_name()
            .to_str()
            .unwrap_or("?")
            .to_string();

        let key_path = entry.path().join("keypair");
        let pid = match IdentityKeypair::load_from_file(&key_path) {
            Ok(kp) => kp.peer_id().to_string(),
            Err(_) => "(no keypair)".to_string(),
        };

        let addr = match load_peer_config(&name) {
            Ok(c) => c.peer.listen_addr,
            Err(_) => "?".to_string(),
        };

        println!("{:<20} {} ({})", name, pid, addr);
        found = true;
    }

    if !found {
        println!("no peers found");
    }

    Ok(())
}

/// Show details for a specific peer.
pub fn show(name: &str) -> anyhow::Result<()> {
    let dir = config::peer_dir(name);
    if !dir.exists() {
        anyhow::bail!("peer '{}' not found", name);
    }

    let key_path = dir.join("keypair");
    let keypair = IdentityKeypair::load_from_file(&key_path)?;

    let peer_toml = load_peer_config(name)?;

    let storage = peer_toml
        .storage
        .as_ref()
        .map(|s| s.backend.as_str())
        .unwrap_or("memory");

    println!("name:       {}", name);
    println!("peer_id:    {}", keypair.peer_id());
    println!("listen:     {}", peer_toml.peer.listen_addr);
    println!("storage:    {}", storage);
    println!("dir:        {}", dir.display());

    Ok(())
}

/// Parse a history flag value: "pattern[:max_depth]"
///
/// Examples:
///   "*"         → pattern="*", max_depth=None
///   "*:1000"    → pattern="*", max_depth=Some(1000)
///   "project/*" → pattern="project/*", max_depth=None
fn parse_history_flag(spec: &str) -> anyhow::Result<(String, Option<u64>)> {
    if let Some(colon_idx) = spec.rfind(':') {
        let pattern = &spec[..colon_idx];
        let depth_str = &spec[colon_idx + 1..];
        // Only treat as pattern:depth if the part after : is a valid number.
        // This avoids misinterpreting patterns like "*/project/*" as having a depth.
        if let Ok(depth) = depth_str.parse::<u64>() {
            if pattern.is_empty() {
                anyhow::bail!("history pattern cannot be empty");
            }
            return Ok((pattern.to_string(), Some(depth)));
        }
    }
    if spec.is_empty() {
        anyhow::bail!("history pattern cannot be empty");
    }
    Ok((spec.to_string(), None))
}

/// Parse the `--files` flag in `name:/fs/path:tree/prefix/` format.
/// Matches the Go peer's parser shape so cross-impl tooling carries over.
fn parse_files_flag(value: &str) -> anyhow::Result<(String, String, String)> {
    // Find the first ':' (separates name) and the last ':' (separates prefix).
    let first = value.find(':').ok_or_else(|| {
        anyhow::anyhow!("--files expects name:/fs/path:tree/prefix/")
    })?;
    let last = value.rfind(':').unwrap();
    if first == last {
        anyhow::bail!("--files expects name:/fs/path:tree/prefix/");
    }
    let name = value[..first].to_string();
    let fs_path = value[first + 1..last].to_string();
    let mut prefix = value[last + 1..].to_string();
    if !prefix.ends_with('/') {
        prefix.push('/');
    }
    if name.is_empty() || fs_path.is_empty() || prefix == "/" {
        anyhow::bail!("--files name, path, and prefix must be non-empty");
    }
    Ok((name, fs_path, prefix))
}

/// Phase P: build a signed `system/peer/published-root` over the served
/// subtree. Returns `(head_hash, seq)`.
///
/// An empty subtree still publishes the canonical empty CHAMP root — that node
/// is a real entity with a stable content hash, so `MANIFEST_GET` and the
/// closure-of-signed-root `CONTENT_GET(root_hash)` both resolve (NETWORK
/// §6.5.6 Amendment 10 / validate-peer published_root v4 + v7). A publisher
/// that refused to publish an empty tree would 404 those and break a
/// consumer's §1.1 walk before the first node.
///
/// The trie is keyed by peer-prefix-stripped paths (e.g. a binding at
/// `/{peer}/system/content/public/x` keys as `system/content/public/x`). This
/// mirrors the root_tracker key convention; the cross-impl key convention is a
/// validate-peer reconcile item (see docs/SPEC-AMBIGUITIES.md).
/// Self-publish the local TCP transport profile at
/// `/{pid}/system/peer/transport/{own_identity_hex}/primary`
/// (EXTENSION-NETWORK §6.5.2a). The `endpoint.url` advertises the bound
/// TCP listener; the §6.5.1 enum fields (`supported_ops`, `freshness`,
/// `nonce_required`, `cap_flow`) are populated by `for_local_listener`.
fn publish_self_tcp_profile(
    peer: &entity_core::peer::Peer,
    tcp_addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let peer_id = peer.peer_id();
    let pid = peer_id.as_str();
    let identity_hex = peer_id
        .identity_hex_local()
        .ok_or_else(|| anyhow::anyhow!("cannot derive local identity hex for transport path"))?;

    let advertised_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let profile = entity_core::peer::transport_profile::TcpProfileData::for_local_listener(
        pid,
        format!("tcp://{}", tcp_addr),
        advertised_at,
    );
    let entity = profile.to_entity();
    let hash = peer
        .content_store()
        .put(entity)
        .map_err(|e| anyhow::anyhow!("store transport profile: {e}"))?;
    let path = format!("/{}/system/peer/transport/{}/primary", pid, identity_hex);
    peer.location_index().set(&path, hash);
    println!("  transport: {} → tcp://{}", path, tcp_addr);
    Ok(())
}

fn publish_served_root(
    peer: &entity_core::peer::Peer,
    serve_namespace: Option<&str>,
) -> anyhow::Result<(entity_core::hash::Hash, u64)> {
    use std::collections::BTreeMap;

    let shared = peer.shared();
    let pid = peer.peer_id().as_str().to_string();
    let peer_prefix = format!("/{}/", pid);
    // --serve-closure-root (no namespace) publishes over the whole peer
    // subtree; --serve-namespace scopes to one content namespace.
    let qualified_prefix = match serve_namespace {
        Some(ns) => format!("{}{}/", peer_prefix, ns.trim_matches('/')),
        None => peer_prefix.clone(),
    };

    let mut bindings = BTreeMap::new();
    for entry in shared.location_index.list(&qualified_prefix) {
        let key = entry
            .path
            .strip_prefix(&peer_prefix)
            .unwrap_or(&entry.path)
            .to_string();
        bindings.insert(key, entry.hash);
    }

    let root = entity_core::tree::trie::build_trie(shared.content_store.as_ref(), &bindings)
        .map_err(|e| anyhow::anyhow!("build_trie: {}", e))?;
    let head = peer
        .publish_root(root)
        .map_err(|e| anyhow::anyhow!("publish_root: {}", e))?;
    let seq = shared
        .content_store
        .get(&head)
        .and_then(|e| entity_core::types::PublishedRootData::from_entity(&e).ok())
        .map(|d| d.seq)
        .unwrap_or(0);
    Ok((head, seq))
}

/// Issue a curated peer-issued registry binding (PROPOSAL-PEER-ISSUED §3.2).
///
/// The registry is just a peer; its identity key IS `K_registry`. This signs a
/// `bind_name → target_peer_id` binding with that key and publishes the binding
/// body + invariant-pointer signature + by-name pointer into the peer's tree —
/// the artifacts the `peer-issued` resolve backend reads + verifies. Serve the
/// result as a coral-reef (`peer start … --serve-namespace system/registry`).
pub fn issue_binding(
    name: &str,
    bind_name: &str,
    target_peer_id: &str,
    transports: &[String],
    ttl_ms: Option<u64>,
    storage_override: Option<&str>,
    hash_type: &str,
) -> anyhow::Result<()> {
    use entity_core::types::SignatureData;
    use entity_registry::data::KIND_PEER_ISSUED;
    use entity_registry::{
        binding_body_path, by_name_pointer_path, normalize_name, signature_pointer_path,
        validate_name_safety, BindingData,
    };

    let dir = config::peer_dir(name);
    if !dir.exists() {
        anyhow::bail!(
            "peer '{}' not found. Run `entity peer init {}` first",
            name,
            name
        );
    }

    // K_registry = this peer's identity. Clone the secret so it survives the
    // `identity_keypair(...)` move into the builder (used to sign + derive paths).
    let key_path = dir.join("keypair");
    let keypair = IdentityKeypair::load_from_file(&key_path)?;
    let signer = keypair.clone_identity();
    let registry_pid = keypair.peer_id();
    let registry_id = registry_pid.as_str();

    // §6.3 name-path safety + NFC normalization (resolver normalizes identically,
    // so `:resolve` and this `:issue` agree on the storage key).
    validate_name_safety(bind_name).map_err(|e| anyhow::anyhow!("invalid name: {e}"))?;
    let norm = normalize_name(bind_name, "none");

    // Home content_hash_format — MUST match what `peer start` serves under so the
    // binding hashes the consumer fetch reproduces are identical (V7 §1.2/§4.5).
    let home_hash_format = match hash_type {
        "sha256" | "ecfv1-sha256" => entity_core::hash::HASH_ALGORITHM_SHA256,
        "sha384" | "ecfv1-sha384" => entity_core::hash::HASH_ALGORITHM_SHA384,
        other => anyhow::bail!(
            "unsupported --hash-type {:?} (expected \"sha256\" or \"sha384\")",
            other
        ),
    };
    entity_core::hash::set_default_hash_format(home_hash_format);

    // Build the peer (no listeners) to reach the same persistent store `start`
    // serves from.
    let peer_toml = load_peer_config(name)?;
    let peer_config = PeerConfig {
        home_hash_format,
        ..PeerConfig::default()
    };
    let mut builder = PeerBuilder::new()
        .identity_keypair(keypair)
        .config(peer_config);

    let storage_backend = storage_override
        .map(|s| s.to_string())
        .or_else(|| peer_toml.storage.as_ref().map(|s| s.backend.clone()))
        .unwrap_or_else(|| "memory".to_string());
    #[cfg(feature = "sqlite")]
    if storage_backend == "sqlite" {
        let db_file = peer_toml
            .storage
            .as_ref()
            .and_then(|s| s.path.as_deref())
            .unwrap_or("store.db");
        builder = builder.sqlite(dir.join(db_file))?;
    }
    #[cfg(not(feature = "sqlite"))]
    if storage_backend == "sqlite" {
        anyhow::bail!("sqlite storage requires the 'sqlite' feature (not compiled in)");
    }
    if storage_backend != "sqlite" {
        eprintln!(
            "warning: storage backend is '{}'; the binding will NOT persist for \
             `peer start` to serve. Pass --storage sqlite.",
            storage_backend
        );
    }
    let peer = builder.build()?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // 1. binding body.
    let binding = BindingData {
        name: norm.clone(),
        kind: KIND_PEER_ISSUED.to_string(),
        target_peer_id: target_peer_id.to_string(),
        transports: transports
            .iter()
            .map(|t| entity_core::ecf::text(t))
            .collect(),
        issued_at: now_ms,
        ttl: ttl_ms,
        supersedes: None,
        issuer_attestation: None,
        metadata: None,
    };
    let binding_entity = binding
        .to_entity()
        .map_err(|e| anyhow::anyhow!("encode binding: {e}"))?;
    let binding_hash = binding_entity.content_hash;
    peer.content_store().put(binding_entity)?;

    // 2. invariant-pointer signature, signed by K_registry over the binding hash.
    let sig = SignatureData {
        target: binding_hash,
        signer: signer.peer_identity_hash(),
        algorithm: signer.key_type().label().to_string(),
        signature: signer.sign(&binding_hash.to_bytes()),
    };
    let sig_entity = sig
        .to_entity()
        .map_err(|e| anyhow::anyhow!("encode signature: {e}"))?;
    let sig_hash = sig_entity.content_hash;
    peer.content_store().put(sig_entity)?;

    // Ensure the registry's identity entity is content-addressable for verifiers
    // (resolve_peer_pubkey follows sig.signer). Idempotent / content-addressed.
    peer.content_store().put(signer.peer_entity()?)?;

    // 3. tree pointers: §3 universal binding-body path + §2.2 by-name index +
    //    V7 §5.2 signature invariant-pointer.
    peer.location_index()
        .set(&binding_body_path(registry_id, &binding_hash), binding_hash);
    peer.location_index()
        .set(&by_name_pointer_path(registry_id, &norm), binding_hash);
    peer.location_index()
        .set(&signature_pointer_path(registry_id, &binding_hash), sig_hash);

    println!("issued peer-issued binding");
    println!("  registry : {registry_id}");
    println!("  name     : {norm}");
    println!("  target   : {target_peer_id}");
    println!("  binding  : {}", binding_hash.to_hex());
    println!("  signature: {}", sig_hash.to_hex());
    if let Some(ttl) = ttl_ms {
        println!("  ttl_ms   : {ttl}");
    }
    Ok(())
}
