//! Per-connection handshake + message loop.

use std::collections::HashMap;
use std::sync::Arc;

use entity_entity::{EntityUri, Envelope};
use entity_handler::{
    ExecuteFn, ExecuteOptions, HandlerContext, HandlerError,
    STATUS_BAD_REQUEST, STATUS_FORBIDDEN, STATUS_INTERNAL_ERROR, STATUS_NOT_FOUND,
    STATUS_NOT_SUPPORTED,
};
use entity_protocol::{
    build_error_response, build_execute_response, build_execute_response_full, Connection,
};
use crate::durability;
use entity_wire::{
    decode_envelope, encode_envelope, read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE,
};
use crate::transport::Connection as TransportConnection;
use crate::{PeerError, PeerShared};

/// Handle a single connection: handshake then message loop.
///
/// Accepts any transport's Connection (TCP, WebSocket, memory, etc.).
/// The wire codec (read_frame/write_frame) works over any AsyncRead/AsyncWrite.
#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(transport = conn.transport_type, remote = %conn.remote_addr),
)]
pub async fn handle_connection(
    conn: TransportConnection,
    shared: Arc<PeerShared>,
) -> Result<(), PeerError> {
    let (mut reader, mut writer) = (conn.reader, conn.writer);

    let mut conn = Connection::new(shared.keypair.peer_id());
    // §4.5: advertise this peer's negotiation surface (home format
    // preference order + key_type accept-set + own key_type for the
    // mutual-verifiability gate). `process_hello` resolves the active
    // `content_hash_format` from this against the initiator's hello.
    conn.set_local_advertisement(
        shared.config.home_hash_format,
        shared.keypair.key_type().label(),
    );

    // --- Phase 1+2: Receive remote hello → send our hello response ---
    tracing::debug!("awaiting remote hello");
    let frame = read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("read hello: {}", e)))?;
    let hello_envelope = decode_envelope(&frame)
        .map_err(|e| PeerError::ConnectionError(format!("decode hello: {}", e)))?;

    // v7.66 §4.4 surface 6 — handshake errors MUST surface as a wire
    // EXECUTE_RESPONSE (e.g., `400 unsupported_key_type` for an unknown
    // remote `key_type`) rather than a transport-level EOF. Build the
    // error response from the inbound request_id, send it on the wire,
    // THEN return the error to close the connection cleanly.
    let hello_response = match build_hello_response_envelope(&hello_envelope, &mut conn) {
        Ok(env) => env,
        Err(e) => {
            let err_env =
                handshake_error_envelope(&hello_envelope, &e, "handshake_failed");
            let frame = encode_envelope(&err_env);
            let _ = write_frame(&mut writer, &frame).await;
            return Err(PeerError::ConnectionError(format!("process hello: {}", e)));
        }
    };
    let response_frame = encode_envelope(&hello_response);
    write_frame(&mut writer, &response_frame)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("write hello response: {}", e)))?;

    // --- Phase 3+4: Receive authenticate → send authenticate response ---
    tracing::debug!("awaiting remote authenticate");
    let frame = read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("read authenticate: {}", e)))?;
    let auth_envelope = decode_envelope(&frame)
        .map_err(|e| PeerError::ConnectionError(format!("decode authenticate: {}", e)))?;

    let auth_response =
        match build_authenticate_response_envelope(&auth_envelope, &mut conn, &shared) {
            Ok(env) => env,
            Err(e) => {
                let err_env =
                    handshake_error_envelope(&auth_envelope, &e, "authentication_failed");
                let frame = encode_envelope(&err_env);
                let _ = write_frame(&mut writer, &frame).await;
                return Err(PeerError::ConnectionError(format!(
                    "process authenticate: {}",
                    e
                )));
            }
        };
    let auth_frame = encode_envelope(&auth_response);
    write_frame(&mut writer, &auth_frame)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("write auth response: {}", e)))?;

    // `remote_peer_id` is now populated on conn after authenticate.
    let remote_peer_id = conn
        .remote_peer_id
        .clone()
        .expect("remote_peer_id set after process_authenticate");
    tracing::info!("handshake complete with {}", remote_peer_id);

    // --- Message loop ---
    //
    // V7 §4.8 (v7.48) — inbound frame processing concurrency invariant.
    // The inbound frame reader MUST NOT block on outbound dispatch on the
    // same connection. Dispatch is spawned; the writer half lives in its
    // own task and serializes outbound frames through an mpsc channel.
    // Concurrency is bounded by a semaphore (MAY clause).
    tracing::debug!(remote_peer = %remote_peer_id, "entering message loop");

    let (resp_tx, mut resp_rx) =
        tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    // Writer task: drains the response channel and writes frames serially.
    let writer_peer_id = remote_peer_id.clone();
    crate::runtime::spawn(async move {
        while let Some(frame) = resp_rx.recv().await {
            tracing::trace!(remote_peer = %writer_peer_id, response_size = frame.len(), "sending response");
            if let Err(e) = write_frame(&mut writer, &frame).await {
                tracing::warn!(remote_peer = %writer_peer_id, error = %e, "writer task: write failed; closing");
                break;
            }
        }
    });

    // Bound dispatch concurrency. The §4.8 MAY clause permits this; the
    // bound keeps a flood of inbound EXECUTEs from spawning unbounded
    // dispatch tasks. The number is intentionally generous — the goal is
    // backpressure, not serialization.
    let dispatch_sem = Arc::new(tokio::sync::Semaphore::new(64));

    // --- §6.11(b) reentry endpoint over this accepted connection ---
    //
    // GUIDE-CONFORMANCE §7a / V7 §6.11(b): a handler dispatching back to the
    // peer that dialed us must reuse THIS socket — that peer may run no
    // listener (the validator's B-role-no-listener case). Register a
    // bidirectional endpoint sharing the serial writer channel (`resp_tx`)
    // and a demux table (`reentry_pending`); the read loop below routes
    // inbound EXECUTE_RESPONSE frames into that table. `get_or_connect`
    // falls back to this endpoint when the peer has no dialable transport.
    let reentry_pending = crate::remote::new_pending();
    let reentry_endpoint: Option<Arc<dyn crate::remote::RemoteEndpoint>> = {
        // Guaranteed Some — `build_authenticate_response_envelope` required it.
        let remote_identity_hash = conn
            .remote_identity_hash
            .expect("remote identity hash set after authenticate");
        // Placeholder connection cap (never read on the reentry path —
        // dispatch always supplies the explicit §7a.2a cap). Prefer the
        // connection cap we just minted; fall back to our identity entity.
        let placeholder_cap = match auth_response
            .included
            .values()
            .find(|e| e.entity_type == entity_types::TYPE_CAP_TOKEN)
        {
            Some(c) => Some(c.clone()),
            None => shared.keypair.peer_entity().ok(),
        };
        match placeholder_cap {
            Some(cap) => {
                let endpoint: Arc<dyn crate::remote::RemoteEndpoint> =
                    Arc::new(crate::remote::InboundReentryEndpoint::new(
                        remote_peer_id.to_string(),
                        remote_identity_hash,
                        cap,
                        resp_tx.clone(),
                        reentry_pending.clone(),
                    ));
                shared
                    .remote
                    .register_inbound(remote_peer_id.as_str(), endpoint.clone());
                Some(endpoint)
            }
            None => {
                tracing::warn!(
                    remote_peer = %remote_peer_id,
                    "reentry: could not build endpoint cap; reentry disabled for this connection"
                );
                None
            }
        }
    };
    // Tear down the reentry endpoint whenever this connection loop exits
    // (clean EOF, read error, or task abort). Two responsibilities:
    //   1. Deregister *our* endpoint — identity-checked so a second inbound
    //      connection from the same peer that overwrote the map entry is not
    //      clobbered by this (older) connection's teardown.
    //   2. Clear `reentry_pending` so any in-flight reentry caller resolves
    //      immediately with a connection error instead of blocking to the
    //      request timeout (mirrors the dialer-side `spawn_reader_loop`).
    struct ReentryGuard {
        shared: Arc<PeerShared>,
        peer_id: String,
        endpoint: Option<Arc<dyn crate::remote::RemoteEndpoint>>,
        pending: crate::remote::Pending,
    }
    impl Drop for ReentryGuard {
        fn drop(&mut self) {
            if let Some(ep) = &self.endpoint {
                self.shared.remote.remove_inbound(&self.peer_id, ep);
            }
            self.pending.lock().unwrap().clear();
        }
    }
    let _reentry_guard = ReentryGuard {
        shared: shared.clone(),
        peer_id: remote_peer_id.to_string(),
        endpoint: reentry_endpoint,
        pending: reentry_pending.clone(),
    };

    loop {
        let frame = match read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE).await {
            Ok(f) => f,
            Err(entity_wire::WireError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                tracing::debug!(remote_peer = %remote_peer_id, "remote disconnected (EOF)");
                return Ok(()); // Clean disconnect
            }
            Err(e) => {
                return Err(PeerError::ConnectionError(format!("read frame: {}", e)));
            }
        };

        tracing::trace!(remote_peer = %remote_peer_id, frame_size = frame.len(), "received frame");

        let envelope = match decode_envelope(&frame) {
            Ok(e) => {
                // GUIDE-INSPECTABILITY v1.2 §2.1 #5 wire-recv hook —
                // success path with the envelope's request_id.
                let req_id = extract_request_id(&e).unwrap_or_default();
                fire_wire_hooks(
                    &shared,
                    crate::WireDirection::Recv,
                    &req_id,
                    &frame,
                    remote_peer_id.as_str(),
                );
                e
            }
            Err(e) => {
                // §2.1 #5 wire-recv hook — failure path. Per spec "every
                // inbound frame" — malformed frames fire with empty
                // request_id. This is the F-CIMP-7-class observability
                // case (bytes-on-wire diverged from expected shape) the
                // wire recorder exists to catch.
                fire_wire_hooks(
                    &shared,
                    crate::WireDirection::Recv,
                    "",
                    &frame,
                    remote_peer_id.as_str(),
                );
                tracing::warn!(remote_peer = %remote_peer_id, error = %e, "failed to decode envelope");
                continue;
            }
        };

        // §6.11(b) reentry: an inbound EXECUTE_RESPONSE is the reply to an
        // outbound EXECUTE this peer originated back over the accepted
        // connection (via InboundReentryEndpoint). Route it to the waiting
        // dispatcher instead of treating it as a request (which would error).
        if envelope.root.entity_type == entity_types::TYPE_EXECUTE_RESPONSE {
            match entity_protocol::parse_execute_response(&envelope) {
                Ok(resp) => {
                    let rid = resp.request_id.clone();
                    let sender = reentry_pending.lock().unwrap().remove(&rid);
                    match sender {
                        Some(tx) => {
                            let _ = tx.send(resp);
                        }
                        None => tracing::warn!(
                            remote_peer = %remote_peer_id,
                            request_id = %rid,
                            "reentry: EXECUTE_RESPONSE with no pending waiter — dropped"
                        ),
                    }
                }
                Err(e) => tracing::warn!(
                    remote_peer = %remote_peer_id,
                    error = %e,
                    "reentry: failed to parse inbound EXECUTE_RESPONSE — dropped"
                ),
            }
            continue;
        }

        // Spawn dispatch — the §4.8 invariant fix. Each frame's handler runs
        // concurrently with subsequent reads; the writer task serializes
        // responses back onto the wire.
        let shared_task = shared.clone();
        let resp_tx_task = resp_tx.clone();
        let sem_task = dispatch_sem.clone();
        let remote_peer_id_task = remote_peer_id.clone();
        crate::runtime::spawn(async move {
            let _permit = match sem_task.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return, // semaphore closed → shutting down
            };
            let response_envelope =
                dispatch_request(&envelope, shared_task.clone(), Some(remote_peer_id_task.as_str()))
                    .await;
            let response_frame = encode_envelope(&response_envelope);
            // §2.1 #5 wire-send hook. Fires before pushing the frame onto
            // the writer channel — the envelope is in scope so request_id
            // is recoverable.
            let send_req_id = extract_request_id(&response_envelope).unwrap_or_default();
            fire_wire_hooks(
                &shared_task,
                crate::WireDirection::Send,
                &send_req_id,
                &response_frame,
                remote_peer_id_task.as_str(),
            );
            if resp_tx_task.send(response_frame).is_err() {
                tracing::debug!(remote_peer = %remote_peer_id_task, "writer task gone; dropping response");
            }
        });
    }
}

/// Build the hello-response envelope for a received hello EXECUTE.
///
/// Used by both the stream transports (TCP / WS / memory) inside
/// [`handle_connection`] and by the HTTP-live transport via
/// [`dispatch_session_envelope`]. Mutates `conn.state` from
/// `AwaitingHello` to `AwaitingAuthenticate` on success.
pub(crate) fn build_hello_response_envelope(
    hello_envelope: &Envelope,
    conn: &mut Connection,
) -> Result<Envelope, PeerError> {
    let (our_hello, hello_request_id) = conn
        .process_hello(hello_envelope)
        .map_err(PeerError::Protocol)?;
    tracing::debug!(request_id = %hello_request_id, "received remote hello, building hello response");

    let our_hello_entity = our_hello
        .to_entity()
        .map_err(|e| PeerError::ConnectionError(format!("build hello entity: {}", e)))?;
    let hello_response = build_execute_response(&hello_request_id, 200, our_hello_entity)
        .map_err(|e| PeerError::ConnectionError(format!("build hello response: {}", e)))?;
    Ok(hello_response)
}

/// Build the authenticate-response envelope for a received authenticate
/// EXECUTE.
///
/// Per spec §4.4, the response carries an EXECUTE_RESPONSE whose
/// `result` is a `system/capability/grant` and whose `included` map
/// has the capability token entity + local identity + capability
/// signature. The capability is built from the configured grant
/// resolver (EXTENSION-ROLE §4.7 initial-grant policy) with a static
/// fallback (debug_open_grants in dev, otherwise default_connection_
/// grants).
///
/// Mutates `conn.state` from `AwaitingAuthenticate` to `Established`
/// on success and sets `conn.remote_peer_id` + `conn.remote_public_key`.
pub(crate) fn build_authenticate_response_envelope(
    auth_envelope: &Envelope,
    conn: &mut Connection,
    shared: &Arc<PeerShared>,
) -> Result<Envelope, PeerError> {
    let (remote_peer_id, auth_request_id) = conn
        .process_authenticate(auth_envelope)
        .map_err(PeerError::Protocol)?;

    tracing::info!("authenticated remote peer: {}", remote_peer_id);

    // §4.5a: author the local identity under the connection's negotiated
    // active `content_hash_format` (not the peer's home-format startup
    // identity), so the granter/signer references we mint are in the one
    // format in play on this connection.
    let active_format = conn.active_hash_format;
    let local_identity = shared
        .keypair
        .peer_entity_with_format(active_format)
        .map_err(|e| PeerError::ConnectionError(format!("build identity: {}", e)))?;

    // V7 §1.8 (v7.69): the cap `grantee` is the remote's **authored**
    // identity `content_hash` — the `signature.signer` we just verified in
    // `process_authenticate` — NOT a re-derivation under our local format.
    // Re-deriving would manufacture a second content_hash for one identity
    // and break the `grantee == author` equality on a cross-format
    // connection (the precise §1.8 violation v7.69 names). Under §4.5a the
    // active format is one value for the connection, so the authored remote
    // identity is already in `active_format`.
    let grantee_hash = conn
        .remote_identity_hash
        .ok_or_else(|| PeerError::ConnectionError("remote identity hash not captured".into()))?;

    // Connection grants (resolver-first, static fallback). Matches
    // the recognize-on-attestation handoff §7 / Go's reference.
    let static_fallback = || {
        if shared.config.debug_open_grants {
            tracing::warn!("using debug open grants — all operations permitted");
            entity_capability::debug_open_grants()
        } else {
            entity_capability::default_connection_grants()
        }
    };
    let mut grants = if let Some(resolver) = shared.grant_resolver.as_ref() {
        match resolver(&remote_peer_id, &grantee_hash) {
            Some(g) => {
                tracing::debug!(
                    grant_count = g.len(),
                    "grant resolver returned connection grants"
                );
                g
            }
            None => static_fallback(),
        }
    } else {
        static_fallback()
    };
    // V7.62 §4.4 policy-table consultation: union the SHOULD floor with
    // any matched `system/capability/policy/{peer_pattern}` entry for
    // the connecting peer. Conditional on the capability handler being
    // registered (no-op when absent — backward-compat for peers without
    // the §6.2 handler).
    if shared
        .handler_registry
        .get(&format!("/{}/system/capability", shared.peer_id))
        .is_some()
    {
        if let Some(extras) = lookup_capability_policy_grants(
            shared,
            &grantee_hash,
            remote_peer_id.as_str(),
        ) {
            tracing::debug!(
                added = extras.len(),
                "§4.4 union: policy entry added grants to initial scope"
            );
            grants.extend(extras);
        }
    }
    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // R6 (PROPOSAL §9 rulings) — session+capability as tree entity.
    //
    // Granter side: I'm being dialed. After authenticating remote, I
    // mint (or reuse, per R3a) the connection-handshake cap and record
    // it as `minted_capability` on
    // `/{local_peer_id}/system/peer/session/{remote_peer_id}`.
    //
    // Flow: probe the session path; on hit with `minted_capability`
    // pointing to a live cap whose grants match what we'd grant now,
    // reuse the cap entity. Otherwise mint fresh + write/update the
    // session entity (preserving any pre-existing `held_capability`
    // from a prior outbound dial to this peer).
    //
    // §9.1 R6-a (reconciliation with §7.1 #2, load-bearing):
    // `minted_capability` is granter bookkeeping (R3a idempotency
    // anchor), NOT a back-delivery cap. Back-direction delivery uses
    // `deliver_token`, unchanged.
    // v7.64 §1.4: path-segment is hex of remote's `system/peer` content_hash.
    let session_path = format!(
        "/{}/{}",
        shared.peer_id,
        crate::session_entity::PeerSession::relative_path(&grantee_hash)
    );
    let existing_session = shared.tree.get(&session_path).and_then(|e| {
        match crate::session_entity::PeerSession::from_entity(&e) {
            Ok(s) => Some(s),
            Err(err) => {
                tracing::warn!(
                    path = %session_path,
                    error = %err,
                    "R6: existing session entity failed to decode; minting fresh"
                );
                None
            }
        }
    });
    let reused_cap_entity = existing_session.as_ref().and_then(|session| {
        let minted = session.minted_capability.as_ref()?;
        let cap_entity = shared.content_store.get(&minted.hash)?;
        if !cap_is_live(&cap_entity, now_ms) {
            return None;
        }
        // §4.5a item 5: a cap chain has a self-consistent content_hash_format
        // and does not cross format boundaries. A cached cap minted under a
        // format other than this connection's active format MUST NOT be
        // reused — mint fresh under the active format.
        if cap_entity.content_hash.algorithm != active_format {
            tracing::debug!(
                path = %session_path,
                cached = cap_entity.content_hash.algorithm,
                active = active_format,
                "R6/§4.5a: cached cap format != connection active; minting fresh"
            );
            return None;
        }
        let cached_token =
            entity_capability::CapabilityToken::from_entity(&cap_entity).ok()?;
        // Grants-changed check (§9.1 R6-e — mint fresh + overwrite).
        if cached_token.grants != grants {
            tracing::debug!(
                path = %session_path,
                "R6: cached session grants differ from current; minting fresh"
            );
            return None;
        }
        tracing::debug!(
            grantee = %remote_peer_id,
            token = %cap_entity.content_hash,
            "R6: reusing minted cap via session entity"
        );
        Some(cap_entity)
    });

    let cap_entity = if let Some(entity) = reused_cap_entity {
        entity
    } else {
        let cap_token = entity_capability::CapabilityToken {
            grants,
            granter: entity_capability::Granter::Single(local_identity.content_hash),
            grantee: grantee_hash,
            parent: None,
            created_at: now_ms,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        let cap_entity = cap_token
            .to_entity_with_format(active_format)
            .map_err(|e| PeerError::ConnectionError(format!("build cap token: {}", e)))?;
        // Persist the cap entity in the content store so future
        // session-entity hits resolve. Put failure is logged + ignored
        // (forces re-mint next handshake; correctness preserved).
        if let Err(e) = shared.content_store.put(cap_entity.clone()) {
            tracing::warn!(
                error = %e,
                "R6: content_store.put(cap_entity) failed; next handshake will remint"
            );
        }
        // Build the minted-cap reference (root cap ⇒ chain length 1).
        let minted_ref = crate::session_entity::CapabilityRef {
            hash: cap_entity.content_hash,
            chain: vec![cap_entity.content_hash],
        };
        // Preserve any pre-existing held_capability from an earlier
        // outbound dial to this peer (§9.1 R6-a — one entity per peer,
        // two cap fields, populated from whichever direction handshook).
        let session_to_write = match existing_session {
            Some(prior) => prior.with_minted(minted_ref, now_ms),
            None => crate::session_entity::PeerSession::new_minted(
                remote_peer_id.to_string(),
                grantee_hash,
                conn.remote_public_key.as_ref().map(|pk| pk.to_vec()),
                minted_ref,
                now_ms,
                None,
            ),
        };
        if let Err(e) = shared.tree.put(&session_path, session_to_write.to_entity()) {
            tracing::warn!(
                path = %session_path,
                error = %e,
                "R6: tree.put(session_entity) failed; next handshake will remint"
            );
        }
        cap_entity
    };

    let cap_sig_bytes = shared.keypair.sign(&cap_entity.content_hash.to_bytes());
    let cap_sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("algorithm"),
            entity_ecf::text(shared.keypair.key_type().label()),
        ),
        (
            entity_ecf::text("signature"),
            entity_ecf::Value::Bytes(cap_sig_bytes),
        ),
        (
            entity_ecf::text("signer"),
            entity_ecf::Value::Bytes(local_identity.content_hash.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("target"),
            entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
        ),
    ]));
    let cap_sig_entity = entity_entity::Entity::new_with_format(
        entity_entity::TYPE_SIGNATURE,
        cap_sig_data,
        active_format,
    )
    .map_err(|e| PeerError::ConnectionError(format!("build cap sig: {}", e)))?;

    let grant_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("token"),
        entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
    )]));
    let grant_entity = entity_entity::Entity::new_with_format(
        entity_types::TYPE_CAP_GRANT,
        grant_data,
        active_format,
    )
    .map_err(|e| PeerError::ConnectionError(format!("build grant: {}", e)))?;

    let mut auth_response = build_execute_response(&auth_request_id, 200, grant_entity)
        .map_err(|e| PeerError::ConnectionError(format!("build auth response: {}", e)))?;
    auth_response.include(cap_entity);
    auth_response.include(local_identity);
    auth_response.include(cap_sig_entity);

    Ok(auth_response)
}

/// Decide whether a cap-token entity is still live at `now_ms`.
/// Treats decode failure or absent token as not-live (forces a fresh
/// mint). `expires_at == None` ⇒ no expiry ⇒ live. `not_before` is
/// respected: a token whose `not_before` is in the future is treated
/// as not-live (would be rejected on use anyway).
fn cap_is_live(entity: &entity_entity::Entity, now_ms: u64) -> bool {
    if entity.entity_type != entity_types::TYPE_CAP_TOKEN {
        return false;
    }
    let token = match entity_capability::CapabilityToken::from_entity(entity) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if let Some(expires_at) = token.expires_at {
        if now_ms >= expires_at {
            return false;
        }
    }
    if let Some(not_before) = token.not_before {
        if now_ms < not_before {
            return false;
        }
    }
    true
}

/// One-envelope-in, one-envelope-out router that routes by the
/// session's [`Connection`] state. This is the entry point for
/// request/response transports (HTTP) where each request is a
/// separate POST and the session is correlated by an out-of-band ID
/// (e.g., `X-Entity-Session`).
///
/// - `AwaitingHello` → [`build_hello_response_envelope`]
/// - `AwaitingAuthenticate` → [`build_authenticate_response_envelope`]
/// - `Established` → [`dispatch_request`] (the standard
///   post-handshake dispatch path TCP / WS also use)
///
/// Handshake errors are converted to error response envelopes so the
/// HTTP layer still returns a wire-decodable body; the caller decides
/// whether to evict the session (e.g., on auth failure).
#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
pub(crate) async fn dispatch_session_envelope(
    envelope: &Envelope,
    conn: &mut Connection,
    shared: Arc<PeerShared>,
) -> Envelope {
    use entity_protocol::ConnectionState;
    let request_id = extract_request_id(envelope).unwrap_or_else(|| "unknown".to_string());
    let result = match conn.state {
        ConnectionState::AwaitingHello => build_hello_response_envelope(envelope, conn),
        ConnectionState::AwaitingAuthenticate => {
            build_authenticate_response_envelope(envelope, conn, &shared)
        }
        ConnectionState::Established => {
            let session_peer_id = conn.remote_peer_id.as_ref().map(|p| p.as_str().to_string());
            return dispatch_request(envelope, shared, session_peer_id.as_deref()).await;
        }
    };
    match result {
        Ok(env) => env,
        Err(e) => {
            tracing::warn!(request_id = %request_id, error = %e, "handshake step failed");
            // v7.66 §4.4 surface 6: shared with the TCP path
            // (`accept_connection`); inner ProtocolError variants
            // (unsupported_key_type, unsupported_content_hash_format)
            // surface via their dedicated registry codes.
            let _ = request_id; // moved into handshake_error_envelope via inbound
            handshake_error_envelope(envelope, &e, "handshake_failed")
        }
    }
}

/// Dispatch a request: verify -> resolve handler -> dispatch -> build response.
#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(
        entity_type = %envelope.root.entity_type,
        request_id = tracing::field::Empty,
        status = tracing::field::Empty,
    ),
)]
pub(crate) async fn dispatch_request(
    envelope: &Envelope,
    shared: Arc<PeerShared>,
    session_peer_id: Option<&str>,
) -> Envelope {
    // Extract request_id for error responses
    let request_id = extract_request_id(envelope).unwrap_or_else(|| "unknown".to_string());
    tracing::Span::current().record("request_id", request_id.as_str());

    tracing::debug!(
        request_id = %request_id,
        entity_type = %envelope.root.entity_type,
        included_count = envelope.included.len(),
        "received request"
    );

    // Trace-level dump of EXECUTE fields for debugging
    if tracing::enabled!(tracing::Level::TRACE) {
        if let Ok(val) = ciborium::from_reader::<ciborium::Value, _>(envelope.root.data.as_slice()) {
            if let Some(map) = val.as_map() {
                let keys: Vec<&str> = map.iter()
                    .filter_map(|(k, _)| k.as_text())
                    .collect();
                tracing::trace!(
                    request_id = %request_id,
                    fields = ?keys,
                    "EXECUTE data fields"
                );
            }
        }
    }

    // Verify the request — V7.62 closeout F2 wires §5.2 Step 4
    // `is_revoked` into verify_request. `supports_revocation = true`
    // because Rust ships the full marker mechanism (capability handler
    // writes markers at `system/capability/revocations/{root_hash_hex}`
    // on revoke). The MUST-level wire-in is what makes wire-only-cap
    // revocation operationally real — markers alone aren't enough.
    let pid_string = shared.keypair.peer_id().as_str().to_string();
    let verify_ctx = entity_protocol::VerifyContext::new(&pid_string).with_revocation(true);
    let store = shared.content_store.clone();
    let li = shared.location_index.clone();
    let included_for_resolve = envelope.included.clone();
    let resolve = |h: &entity_hash::Hash| {
        // Store-first then envelope `included` fallback per V7 §5.1
        // convention for revocation lookups.
        store.get(h).or_else(|| included_for_resolve.get(h).cloned())
    };
    let locate = |path: &str| li.get(path);
    let li_for_scan = shared.location_index.clone();
    let capability_path_for = |h: &entity_hash::Hash| {
        entity_protocol::capability_path_for_scan(h, &pid_string, |prefix| {
            li_for_scan
                .list(prefix)
                .into_iter()
                .map(|e| (e.path, e.hash))
                .collect()
        })
    };
    let verified = match entity_protocol::verify_request_with_ctx(
        envelope,
        &verify_ctx,
        resolve,
        locate,
        capability_path_for,
    ) {
        Ok(v) => v,
        Err(e) => {
            let status = e.wire_status_code();
            // v7.66 §4.4 surface 6: registry-entry codes win over the
            // generic verification_failed default. AGILITY-UNKNOWN-1 +
            // FORMAT-CODE-INTERPRETATION-1 + CAP-FREEZE-1 assert on the
            // dedicated codes returned via `wire_error_code()`.
            let code = e.wire_error_code().unwrap_or("verification_failed");
            tracing::warn!(request_id = %request_id, status = status, error = %e, "request verification failed");
            return build_error_response(&request_id, status, code, &e.to_string())
                .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
        }
    };

    // V7 §6.5: envelope.included signature ingestion. Runs after
    // verify_request (included entities structurally validated) and
    // BEFORE handler resolution. Universal across kernel / substrate /
    // identity / extension ops; substrate handlers can rely on
    // signatures being bound at canonical V7 paths by the time they run.
    if let Err(e) = crate::ingest::ingest_envelope_signatures(
        &envelope.included,
        &shared.content_store,
        &shared.location_index,
    ) {
        let (status, code) = match e {
            crate::ingest::IngestError::SignaturePathConflict { .. } => {
                (STATUS_BAD_REQUEST, "signature_path_conflict")
            }
            crate::ingest::IngestError::Io(_) => (500, "ingest_io_error"),
        };
        tracing::warn!(
            request_id = %verified.request_id,
            status = status,
            error = %e,
            "envelope signature ingestion failed"
        );
        return build_error_response(&verified.request_id, status, code, &e.to_string())
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    }

    // Check for deliver_to early for logging purposes
    let has_deliver_to = extract_deliver_to(&envelope.root).is_some();
    let has_deliver_token = extract_deliver_token(&envelope.root).is_some();
    tracing::debug!(
        request_id = %verified.request_id,
        uri = %verified.uri,
        operation = %verified.operation,
        author = %verified.author_hash,
        deliver_to = has_deliver_to,
        deliver_token = has_deliver_token,
        "request verified"
    );

    // V1: Validate and qualify handler path (R12)
    let bare_path = EntityUri::extract_handler_path(&verified.uri);
    let local_pid = shared.keypair.peer_id();

    // Pre-qualify validation: reject ./, ../, empty segments
    if let Err(msg) = EntityUri::validate_path_input(bare_path) {
        return build_error_response(
            &verified.request_id,
            STATUS_BAD_REQUEST,
            "invalid_path",
            &msg,
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    }

    let handler_path_owned = EntityUri::qualify_path(bare_path, local_pid.as_str());
    let handler_path = handler_path_owned.as_str();

    // Post-qualify validation: verify absolute path structure
    if let Err(msg) = EntityUri::validate_absolute_path(handler_path) {
        return build_error_response(
            &verified.request_id,
            STATUS_BAD_REQUEST,
            "invalid_path",
            &msg,
        )
        .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    }
    let handler_authorized = verified.capability.grants.iter().any(|grant| {
        entity_capability::matches_scope(
            handler_path,
            &grant.handlers.include,
            &grant.handlers.exclude,
            local_pid.as_str(),
        )
    });
    if !handler_authorized {
        tracing::warn!(
            request_id = %verified.request_id,
            handler_path = %handler_path,
            operation = %verified.operation,
            "handler scope authorization denied"
        );
        // v1.19 canonical 403 code: `capability_denied` (V7 §3.3 line 736).
        // WB-27 v1.20 §3.10.3: bind a `rejected`-variant marker when this is
        // a chain dispatch; mirror via ErrorData.rejected_marker.
        return build_capability_denied_response(
            &shared,
            envelope,
            &verified.request_id,
            &verified.author_hash,
            handler_path,
            "capability does not grant access to this handler",
        );
    }

    // Resolve handler
    let resolved = match entity_handler::resolve_handler(
        handler_path,
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
        &shared.handler_registry,
    ) {
        Some(r) => r,
        None => {
            tracing::warn!(
                request_id = %verified.request_id,
                handler_path = %handler_path,
                "no handler found for path"
            );
            return build_error_response(
                &verified.request_id,
                STATUS_NOT_FOUND,
                "handler_not_found",
                &format!("no handler for path: {}", handler_path),
            )
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
        }
    };

    tracing::debug!(
        request_id = %verified.request_id,
        handler = %resolved_handler_name(&resolved),
        pattern = %resolved.pattern,
        suffix = %resolved.suffix,
        operation = %verified.operation,
        compiled = resolved.handler.is_some(),
        "handler resolved"
    );

    // V2: Parse, qualify, and validate resource target paths (R12)
    let resource_target = match extract_resource_target(&envelope.root) {
        Some(mut rt) => {
            let pid = shared.keypair.peer_id();
            let mut qualified_targets = Vec::with_capacity(rt.targets.len());
            for t in &rt.targets {
                // Pre-qualify validation
                if let Err(msg) = EntityUri::validate_path_input(t) {
                    return build_error_response(
                        &verified.request_id,
                        STATUS_BAD_REQUEST,
                        "invalid_resource_path",
                        &msg,
                    )
                    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                }
                let qualified = EntityUri::qualify_path(t, pid.as_str());
                // Post-qualify validation on non-pattern targets
                if !qualified.contains('*') {
                    if let Err(msg) = EntityUri::validate_absolute_path(&qualified) {
                        return build_error_response(
                            &verified.request_id,
                            STATUS_BAD_REQUEST,
                            "invalid_resource_path",
                            &msg,
                        )
                        .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                    }
                }
                qualified_targets.push(qualified);
            }
            rt.targets = qualified_targets;
            Some(rt)
        }
        None => None,
    };
    let params = extract_params_entity(&envelope.root);

    if let Some(ref rt) = resource_target {
        tracing::debug!(
            request_id = %verified.request_id,
            targets = ?rt.targets,
            "resource target"
        );
    }
    tracing::trace!(
        request_id = %verified.request_id,
        params_type = %params.entity_type,
        params_hash = %params.content_hash,
        params_size = params.data.len(),
        "params entity"
    );

    // Check permission (§5.4) — capability must authorize this operation+handler+resource.
    // Returns the matching grant so handlers can inspect constraints.
    //
    // PR-8 (§5.5): the cap's peer-relative resource patterns canonicalize
    // against the *granter's* namespace, not the verifier's. Resolve the leaf
    // cap's granter peer_id from `envelope.included` (guaranteed present —
    // `verify_request` validated the chain). A foreign-granted bare-`*` cap
    // thus canonicalizes to the granter's namespace and cannot reach this
    // peer's resources. Fail-closed (deny) if the granter is unresolvable.
    let local_pid = shared.keypair.peer_id();
    let matching_grant = match entity_capability::resolve_granter_peer_id(
        &verified.capability.granter,
        local_pid.as_str(),
        |h| envelope.included.get(h),
    ) {
        Some(granter_peer_id) => entity_capability::check_permission_with_grant(
            &verified.operation,
            &resolved.pattern,
            local_pid.as_str(),
            resource_target.as_ref(),
            &verified.capability,
            local_pid.as_str(),
            &granter_peer_id,
        ),
        None => None,
    };
    if matching_grant.is_none() {
        tracing::warn!(
            request_id = %verified.request_id,
            handler = %resolved_handler_name(&resolved),
            operation = %verified.operation,
            resource = ?resource_target.as_ref().map(|r| &r.targets),
            "operation permission denied"
        );
        // v1.19 canonical 403 code + WB-27 v1.20 marker bind for chain dispatches.
        return build_capability_denied_response(
            &shared,
            envelope,
            &verified.request_id,
            &verified.author_hash,
            handler_path,
            "capability does not grant permission for this operation",
        );
    }

    // Extract bounds from the EXECUTE entity (§5.9)
    let bounds = extract_bounds(&envelope.root);

    // Build context and dispatch
    let included: HashMap<entity_hash::Hash, entity_entity::Entity> =
        envelope.included.iter().map(|(h, e)| (*h, e.clone())).collect();
    let execute_fn = make_execute_fn(
        shared.clone(),
        Some(verified.author_hash),
        included.clone(),
        bounds.clone(),
        // V7 §6.8 / proposal §6.2: original caller's verified capability is the
        // attribution context for any sub-dispatches the handler performs.
        Some(verified.capability.clone()),
    );

    // Load + validate handler grant from tree (§6.8, §6.9, §S2/§S3). See
    // `load_local_handler_grant` for the full check ladder: granter equality,
    // signature verification, temporal validity. A failed check yields
    // `(None, None)`, which engages the §7.1 fail-closed path on entity-
    // native dispatch and drops any compiled-handler authority claim from a
    // transferred subtree.
    let bare_pattern = entity_entity::EntityUri::strip_peer_prefix(&resolved.pattern);
    let (handler_grant, handler_grant_hash) = load_local_handler_grant(
        &bare_pattern,
        shared.location_index.as_ref(),
        shared.content_store.as_ref(),
        local_pid.as_str(),
        shared.identity_hash,
        shared.keypair.key_type(),
        &shared.keypair.public_key_bytes(),
    );

    let mut builder = HandlerContext::builder(envelope.root.clone(), params)
        .caller_capability(verified.capability)
        .pattern(resolved.pattern.clone())
        .suffix(resolved.suffix.clone())
        .author(verified.author_hash)
        .request_id(verified.request_id.clone())
        .operation(verified.operation.clone())
        .execute_fn(execute_fn.clone())
        .included(included)
        .capability_hash(verified.capability_hash)
        // PROPOSAL-CONVERGENT-MIRRORING §2.3 D4: this is the inbound wire
        // dispatch entry — receiver-local ops use this signal to refuse
        // cross-peer invocation.
        .is_external(true);
    // RELAY §2.2: the placement identity for a relay :put is the authenticated
    // connection peer, not the wire-author. Threaded from the verified
    // handshake `remote_peer_id`.
    if let Some(sp) = session_peer_id {
        builder = builder.session_peer_id(sp);
    }
    if let Some(g) = handler_grant {
        builder = builder.handler_grant(g);
    }
    if let Some(rt) = resource_target {
        builder = builder.resource_target(rt);
    }
    if let Some(mg) = matching_grant {
        builder = builder.matching_grant(mg);
    }
    if let Some(hgh) = handler_grant_hash {
        builder = builder.handler_grant_hash(hgh);
    }
    if let Some(b) = bounds {
        builder = builder.bounds(b);
    }
    let ctx = builder.build();

    // --- Durability contract (EXTENSION-DURABILITY v0.1, exploratory) ---
    // The request is accepted for processing (verified, handler resolved and
    // authorized). Reconcile any durability marker against the receiver's
    // policy at acceptance (§4). A `deliver_to` makes the durable write
    // asynchronous (the inbox path), so the verdict reports a `committed`
    // promise observable at `(author, request_id)` (§6) rather than a
    // synchronous `applied` level.
    let durability_cbor: Option<Vec<u8>> =
        match durability::extract_durability_request(&envelope.root) {
            Some(dreq) => {
                // §5/§8 / Amendment 1 — `(author, request_id)` dedup. A
                // replayed durable request whose pair matches a previously
                // preserved entry returns 409 with the prior handle echoed.
                // Probe is BEFORE reconcile + handler dispatch so the second
                // request never re-executes (the §5 invariant — no silent
                // double-execution).
                let dedup_key = (
                    verified.author_hash.to_string(),
                    verified.request_id.clone(),
                );
                if let Some(prior_handle) = shared
                    .preserved_requests
                    .lock()
                    .ok()
                    .and_then(|guard| guard.get(&dedup_key).cloned())
                {
                    tracing::info!(
                        request_id = %verified.request_id,
                        prior_handle = %prior_handle,
                        "durability dedup hit — returning 409 with prior handle"
                    );
                    let dur = durability::DurabilityResult {
                        requested: dreq.level.clone(),
                        applied: "stored".to_string(),
                        committed: None,
                        max_available: None,
                        reason: Some(
                            durability::REASON_DUPLICATE_REQUEST_ID.to_string(),
                        ),
                        handle: Some(prior_handle.clone()),
                    };
                    let err_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("code"),
                            entity_ecf::text(durability::REASON_DUPLICATE_REQUEST_ID),
                        ),
                        (
                            entity_ecf::text("message"),
                            entity_ecf::text(format!(
                                "durable (author, request_id) already preserved at {}",
                                prior_handle
                            )),
                        ),
                    ]));
                    let err = entity_entity::Entity::new(
                        entity_types::TYPE_ERROR,
                        err_data,
                    )
                    .unwrap_or_else(|_| envelope.root.clone());
                    return build_execute_response_full(
                        &verified.request_id,
                        entity_handler::STATUS_CONFLICT,
                        err,
                        HashMap::new(),
                        Some(dur.to_cbor()),
                    )
                    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                }

                let mut verdict = durability::reconcile(
                    &dreq,
                    &shared.config.durability_policy,
                    has_deliver_to,
                );
                if verdict.refused() {
                    // §5/§8 — a required durability precondition could
                    // not be met. The operation is **not performed**: refuse
                    // at acceptance, before the handler runs and before any
                    // delivery is spawned. Safe to retry elsewhere, no
                    // double-execution.
                    tracing::warn!(
                        request_id = %verified.request_id,
                        requested = %verdict.result.requested,
                        "durability required but unmet — refusing at acceptance (412)"
                    );
                    let err_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                        (
                            entity_ecf::text("code"),
                            entity_ecf::text(durability::REASON_REQUIRED_UNMET),
                        ),
                        (
                            entity_ecf::text("message"),
                            entity_ecf::text(
                                "required durability level could not be met; \
                                 operation not performed",
                            ),
                        ),
                    ]));
                    let err = entity_entity::Entity::new(
                        entity_types::TYPE_ERROR,
                        err_data,
                    )
                    .unwrap_or_else(|_| envelope.root.clone());
                    return build_execute_response_full(
                        &verified.request_id,
                        verdict.status,
                        err,
                        HashMap::new(),
                        Some(verdict.result.to_cbor()),
                    )
                    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
                }
                // §6 preservation: when the verdict claims durable storage
                // on the synchronous path, write-ahead the originating EXECUTE
                // into the inbox namespace so `(author, request_id)` is a
                // working lookup. The deliver_to path preserves via the inbox
                // handler's own write-ahead (handle_receive at L99-104 of
                // extensions/inbox/src/lib.rs) — don't double-preserve.
                if verdict.preserve() && !has_deliver_to {
                    match preserve_durable_request(
                        &envelope.root,
                        &verified.request_id,
                        &shared,
                    ) {
                        Some(path) => {
                            // §6 / Amendment 1 — the sender follows the handle.
                            // Also record in the dedup index so a replay of
                            // the same `(author, request_id)` returns 409
                            // (§5 / Amendment 1).
                            if let Ok(mut guard) = shared.preserved_requests.lock() {
                                guard.insert(dedup_key.clone(), path.clone());
                            }
                            verdict.result.handle = Some(path);
                        }
                        None => {
                            // Preservation failed — downgrade observably rather
                            // than overclaim `applied` (§5 invariant).
                            tracing::warn!(
                                request_id = %verified.request_id,
                                "durability preservation failed — downgrading applied to none"
                            );
                            verdict.result.applied = "none".to_string();
                            verdict.result.committed = None;
                            verdict.result.reason =
                                Some(durability::REASON_NO_DURABLE_STORE.to_string());
                        }
                    }
                }
                // For the deliver_to / async path: predict where the inbox
                // handler's write-ahead will land. The inbox handler stores
                // at `{deliver_to.uri}/{request_id}` (see
                // `extensions/inbox/src/lib.rs::handle_receive` L99-104).
                // The handle is the address the sender polls (may 404 until
                // commit completes — that's the §6 contract).
                if has_deliver_to && verdict.result.handle.is_none() {
                    if let Some(spec) = extract_deliver_to(&envelope.root) {
                        if !verified.request_id.is_empty() {
                            verdict.result.handle = Some(format!(
                                "{}/{}",
                                spec.uri.trim_end_matches('/'),
                                verified.request_id
                            ));
                        }
                    }
                }
                Some(verdict.result.to_cbor())
            }
            None => None,
        };

    // --- Async delivery detection (INBOX spec §4.5) ---
    // If deliver_to is present, validate deliver_token and return 202 immediately.
    // Process the handler asynchronously and deliver the result to the inbox.
    if let Some(deliver_to) = extract_deliver_to(&envelope.root) {
        // INBOX spec §2.3: deliver_token MUST be present when deliver_to is present
        let deliver_token_hash = match extract_deliver_token(&envelope.root) {
            Some(h) if h != entity_hash::Hash::zero() => h,
            _ => {
                tracing::warn!(
                    request_id = %verified.request_id,
                    "deliver_to present but deliver_token missing"
                );
                return build_error_response(
                    &verified.request_id,
                    STATUS_BAD_REQUEST,
                    "missing_deliver_token",
                    "deliver_to field present but deliver_token is missing",
                )
                .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
            }
        };

        // deliver_token entity must be in included
        if !envelope.included.iter().any(|(h, _)| *h == deliver_token_hash) {
            tracing::warn!(
                request_id = %verified.request_id,
                deliver_token = %deliver_token_hash,
                "deliver_token entity not in envelope included"
            );
            return build_error_response(
                &verified.request_id,
                STATUS_BAD_REQUEST,
                "missing_deliver_token",
                "deliver_token entity not in envelope included",
            )
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
        }

        tracing::debug!(
            request_id = %verified.request_id,
            deliver_uri = %deliver_to.uri,
            deliver_operation = %deliver_to.operation,
            "async delivery: returning 202, processing in background"
        );

        // Spawn async processing task
        let request_id_owned = verified.request_id.clone();
        let handler_name = resolved_handler_name(&resolved).to_string();
        let shared_for_delivery = shared.clone();
        crate::runtime::spawn(async move {
            process_async_delivery(
                ctx,
                &deliver_to,
                &execute_fn,
                &request_id_owned,
                &handler_name,
                shared_for_delivery,
            )
            .await;
        });

        // Return 202 immediately (EXTENSION-INBOX §4.5). When a durability
        // marker was present, the 202 also carries the durability verdict —
        // the durable inbox write completes asynchronously and is observable
        // at `(author, request_id)` (EXTENSION-DURABILITY §5/§6).
        return build_202_response(&verified.request_id, durability_cbor)
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()));
    }

    // --- Synchronous dispatch (normal path) ---
    tracing::debug!(
        request_id = %verified.request_id,
        handler = %resolved_handler_name(&resolved),
        operation = %verified.operation,
        compiled = resolved.handler.is_some(),
        "dispatching to handler"
    );

    // Build the target URI once — used for both dispatch hook events.
    // pattern + suffix matches v1.2 §2.1 #3's `target_uri` field.
    let target_uri = if ctx.suffix.is_empty() {
        ctx.pattern.clone()
    } else if ctx.pattern.ends_with('/') || ctx.suffix.starts_with('/') {
        format!("{}{}", ctx.pattern, ctx.suffix)
    } else {
        format!("{}/{}", ctx.pattern, ctx.suffix)
    };

    // GUIDE-INSPECTABILITY v1.2 §2.1 #3 entry hook. Fires at the
    // dispatcher↔handler-body boundary, before the handler is invoked.
    // Covers both compiled and entity-native dispatch paths because both
    // converge through this match.
    //
    // Hot-path bypass: inline `is_empty()` check avoids the per-dispatch
    // String/clone overhead when no hooks are registered — the common
    // production case.
    if !shared.dispatch_hooks.is_empty() {
        fire_dispatch_hooks(
            &shared,
            &crate::DispatchEvent {
                target_uri: target_uri.clone(),
                operation: ctx.operation.clone(),
                params_hash: ctx.params.content_hash,
                request_id: ctx.request_id.clone(),
                timestamp_ms: dispatch_event_timestamp_ms(),
                phase: crate::DispatchPhase::Entry,
            },
        );
    }

    // V7 §6.5 — compiled handlers in the registry take priority over tree-walked
    // entity-native handlers. resolve_handler already encoded this priority:
    //   - resolved.handler = Some → compiled implementation, dispatch directly.
    //   - resolved.handler = None → tree-only manifest, route entity-native via
    //                               compute evaluator (V7 §6.6, PROPOSAL §1).
    let handler_result = match &resolved.handler {
        Some(handler) => handler.handle(&ctx).await,
        None => {
            #[cfg(feature = "compute")]
            {
                dispatch_tree_only_handler(&resolved, &ctx, shared.clone()).await
            }
            #[cfg(not(feature = "compute"))]
            {
                // Tree-only manifest but compute feature disabled — there's no
                // way to evaluate it. Per V7 §6.6 the manifest is unreachable
                // without the evaluator; treat as not-implemented.
                let _ = (&resolved, &ctx, &shared);
                Err(HandlerError::Internal(
                    "tree-only handler requires the compute feature".to_string(),
                ))
            }
        }
    };

    // §2.1 #3 exit hook. Fires immediately after the handler returns,
    // before response construction. `response_hash` is the result-entity
    // content hash on success; `Hash::zero()` on Err (no result entity
    // produced yet).
    let (exit_status, exit_response_hash) = match &handler_result {
        Ok(r) => (r.status, r.result.content_hash),
        Err(e) => (
            match e {
                HandlerError::InvalidParams(_) => STATUS_BAD_REQUEST,
                HandlerError::NotSupported(_) => STATUS_NOT_SUPPORTED,
                HandlerError::Internal(_) => STATUS_INTERNAL_ERROR,
            },
            entity_hash::Hash::zero(),
        ),
    };
    if !shared.dispatch_hooks.is_empty() {
        fire_dispatch_hooks(
            &shared,
            &crate::DispatchEvent {
                target_uri,
                operation: ctx.operation.clone(),
                params_hash: ctx.params.content_hash,
                request_id: ctx.request_id.clone(),
                timestamp_ms: dispatch_event_timestamp_ms(),
                phase: crate::DispatchPhase::Exit {
                    status: exit_status,
                    response_hash: exit_response_hash,
                },
            },
        );
    }

    match handler_result {
        Ok(result) => {
            tracing::debug!(
                request_id = %verified.request_id,
                handler = %resolved_handler_name(&resolved),
                operation = %verified.operation,
                status = result.status,
                result_type = %result.result.entity_type,
                included_count = result.included.len(),
                "handler completed"
            );
            // Attach the durability verdict when the request carried a
            // durability marker (EXTENSION-DURABILITY §8 — always answer observably).
            build_execute_response_full(
                &verified.request_id,
                result.status,
                result.result,
                result.included,
                durability_cbor,
            )
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()))
        }
        Err(e) => {
            tracing::warn!(
                request_id = %verified.request_id,
                handler = %resolved_handler_name(&resolved),
                operation = %verified.operation,
                error = %e,
                "handler error"
            );
            // Map HandlerError variants to V7 §8.3 status codes:
            //   InvalidParams  → 400 (client sent malformed data)
            //   NotSupported   → 501 (operation not implemented by this handler)
            //   Internal       → 500 (handler-side fault)
            // Previously all variants returned 500, which masked client errors
            // as server errors and confused validator expectations of "≥400".
            let (status, code) = match &e {
                HandlerError::InvalidParams(_) => (STATUS_BAD_REQUEST, "invalid_params"),
                HandlerError::NotSupported(_) => (STATUS_NOT_SUPPORTED, "not_supported"),
                HandlerError::Internal(_) => (STATUS_INTERNAL_ERROR, "handler_error"),
            };
            match durability_cbor {
                // EXTENSION-DURABILITY §8 — even on a handler error, a durability marker is
                // answered observably (the status reports the failure).
                Some(dur) => {
                    let err_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                        (entity_ecf::text("code"), entity_ecf::text(code)),
                        (entity_ecf::text("message"), entity_ecf::text(e.to_string())),
                    ]));
                    let err = entity_entity::Entity::new(
                        entity_types::TYPE_ERROR,
                        err_data,
                    )
                    .unwrap_or_else(|_| envelope.root.clone());
                    build_execute_response_full(
                        &verified.request_id,
                        status,
                        err,
                        HashMap::new(),
                        Some(dur),
                    )
                }
                None => build_error_response(&verified.request_id, status, code, &e.to_string()),
            }
            .unwrap_or_else(|_| Envelope::new(envelope.root.clone()))
        }
    }
}

/// Stable display name for a resolved handler — used in tracing / log fields.
/// Compiled handlers report `Handler::name()`; tree-only manifests fall back
/// to the matched pattern (e.g., `system/validate/entity-native/multi`).
fn resolved_handler_name(resolved: &entity_handler::ResolvedHandler) -> &str {
    resolved
        .handler
        .as_ref()
        .map(|h| h.name())
        .unwrap_or(resolved.pattern.as_str())
}

/// Wall-clock timestamp in Unix milliseconds for `DispatchEvent.timestamp_ms`.
/// Mirrors `extensions/continuation::capture_failure_timestamp_ms`; uses
/// `web_time` so the timestamp is consistent native/wasm32.
fn dispatch_event_timestamp_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Fire all registered dispatch hooks in order. Each closure receives the
/// event by reference; per security audit §2 the hook MUST snapshot any
/// fields it retains. Rust's borrow checker enforces non-retention of the
/// `&DispatchEvent` itself.
///
/// Hot-path bypass: callers wrap construction of the `DispatchEvent` so
/// when `dispatch_hooks` is empty the only work is this one branch +
/// the unconditional event-struct construction (which the optimizer is
/// likely to elide if no hook reads it). For a fully zero-cost bypass,
/// inline the `is_empty()` check at the call site before building the
/// event — see the dispatch sites in `dispatch_request` and
/// `make_execute_fn` for the pattern.
fn fire_dispatch_hooks(shared: &Arc<PeerShared>, event: &crate::DispatchEvent) {
    if shared.dispatch_hooks.is_empty() {
        return;
    }
    for (_name, hook) in &shared.dispatch_hooks {
        hook(event);
    }
}

/// Fire all registered wire hooks. Skips the hot-path overhead (frame
/// clone, timestamp call) entirely when no hooks are registered — the
/// common case in production.
///
/// `request_id` is supplied by the caller — passed empty when the
/// envelope hasn't been (successfully) decoded yet (handshake frames,
/// frames that fail `decode_envelope`). Per GUIDE-INSPECTABILITY v1.2
/// §2.1 #5 "every inbound / outbound frame" — malformed-frame
/// observation is the wire recorder's reason for existing (F-CIMP-7
/// class: bytes-on-the-wire diverged from expected shape).
fn fire_wire_hooks(
    shared: &Arc<PeerShared>,
    direction: crate::WireDirection,
    request_id: &str,
    frame: &[u8],
    peer_address: &str,
) {
    if shared.wire_hooks.is_empty() {
        return;
    }
    let event = crate::WireEvent {
        direction,
        request_id: request_id.to_string(),
        frame_bytes: frame.to_vec(),
        peer_address: peer_address.to_string(),
        timestamp_ms: dispatch_event_timestamp_ms(),
    };
    for (_name, hook) in &shared.wire_hooks {
        hook(&event);
    }
}

/// Process an async delivery: execute handler, wrap result, deliver to inbox.
/// Per INBOX spec §4.1 and §4.5.
/// If deliver_to targets a remote peer, uses outbound connection to deliver.
async fn process_async_delivery(
    ctx: HandlerContext,
    deliver_to: &DeliverySpec,
    execute_fn: &ExecuteFn,
    original_request_id: &str,
    handler_name: &str,
    shared: std::sync::Arc<PeerShared>,
) {
    // Execute the handler via execute_fn (internal dispatch).
    // We re-dispatch to the same handler+operation with the same params.
    // This skips wire auth, which is appropriate since we already verified
    // the original request before spawning this task.
    let handler_path = ctx.pattern.clone();
    let operation = ctx.operation.clone();
    let params = ctx.params.clone();
    let opts = ExecuteOptions {
        resource: ctx.resource_target.clone(),
        request_id: Some(ctx.request_id.clone()),
        ..Default::default()
    };
    let result = execute_fn(handler_path, operation, params, opts).await;

    let (status, result_entity) = match result {
        Ok(r) => {
            tracing::debug!(
                request_id = %original_request_id,
                handler = %handler_name,
                status = r.status,
                "async delivery: handler completed"
            );
            (r.status, r.result)
        }
        Err(e) => {
            tracing::warn!(
                request_id = %original_request_id,
                handler = %handler_name,
                error = %e,
                "async delivery: handler error, dropping delivery"
            );
            return;
        }
    };

    // Build InboxDeliveryData entity (INBOX spec §2.1)
    // The result field carries the handler's result as a full inline entity
    // {content_hash, data, type} — preserving entity identity through the
    // delivery chain. Embedded directly as a CBOR map (not wrapped in a byte
    // string) to match Go's cbor.RawMessage semantics.
    // NOTE: Spec says "primitive/any" for result — spec gap on whether this
    // should be the inline entity or just data. Using inline entity because
    // downstream continuations need type+hash for entity operations (tree.put).
    let result_data_val: entity_ecf::Value =
        ciborium::from_reader(result_entity.data.as_slice())
            .unwrap_or(entity_ecf::Value::Null);
    let result_inline = entity_ecf::Value::Map(vec![
        (entity_ecf::text("content_hash"), entity_ecf::Value::Bytes(result_entity.content_hash.to_bytes().to_vec())),
        (entity_ecf::text("data"), result_data_val),
        (entity_ecf::text("type"), entity_ecf::text(&result_entity.entity_type)),
    ]);
    let delivery_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("original_request_id"),
            entity_ecf::text(original_request_id),
        ),
        (
            entity_ecf::text("result"),
            result_inline,
        ),
        (
            entity_ecf::text("status"),
            entity_ecf::integer(status as i64),
        ),
    ]));
    let delivery_entity = match entity_entity::Entity::new(
        entity_types::TYPE_INBOX_DELIVERY,
        delivery_data,
    ) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                request_id = %original_request_id,
                error = %e,
                "async delivery: failed to build delivery entity"
            );
            return;
        }
    };

    // Check if deliver_to targets a remote peer
    let local_pid = shared.keypair.peer_id();
    let is_remote = crate::remote::is_remote_uri(&deliver_to.uri, local_pid.as_str());

    if is_remote {
        // Remote delivery: resolve address, connect, send authenticated EXECUTE
        tracing::debug!(
            request_id = %original_request_id,
            deliver_uri = %deliver_to.uri,
            "async delivery: remote delivery"
        );

        let remote_peer_id = match crate::remote::extract_peer_id_from_uri(&deliver_to.uri) {
            Some(pid) => pid,
            None => {
                tracing::warn!(
                    request_id = %original_request_id,
                    deliver_uri = %deliver_to.uri,
                    "async delivery: cannot extract peer_id from remote URI"
                );
                return;
            }
        };

        // List what transport profiles we have for debugging. Per
        // §6.5 Amendment 2 + V7 §1.4 v7.64, profiles live at
        // `/{local}/system/peer/transport/{peer_id_hex}/{profile-id}` —
        // narrow the prefix to the remote peer's slot. Identity-form PIDs
        // derive the hex locally; SHA-256-form (Ed448 canonical) recovers
        // it from the cached session entity (v7.67 Phase 2). This block is
        // diagnostics-only — `get_or_connect` below re-resolves through the
        // same path — so a miss here just skips the debug log, never aborts.
        let remote_hex = match crate::remote::resolve_peer_id_hex(
            &remote_peer_id,
            shared.content_store.as_ref(),
            shared.location_index.as_ref(),
            local_pid.as_str(),
        ) {
            Some(h) => h,
            None => {
                tracing::debug!(
                    request_id = %original_request_id,
                    remote_peer = %remote_peer_id,
                    "async delivery: no cached {{peer_id_hex}} for remote yet; get_or_connect will surface the resolution error"
                );
                String::new()
            }
        };
        let transport_prefix = format!(
            "/{}/system/peer/transport/{}/",
            local_pid.as_str(),
            remote_hex
        );
        let transport_entries = shared.location_index.list(&transport_prefix);
        tracing::debug!(
            request_id = %original_request_id,
            remote_peer = %remote_peer_id,
            transport_entries = transport_entries.len(),
            transport_paths = ?transport_entries.iter().map(|e| &e.path).collect::<Vec<_>>(),
            "async delivery: resolving transport address"
        );

        let conn: std::sync::Arc<dyn crate::remote::RemoteEndpoint> =
            match crate::remote::get_or_connect(
                &shared.remote,
                &remote_peer_id,
                &shared.keypair,
                shared.content_store.as_ref(),
                shared.location_index.as_ref(),
                local_pid.as_str(),
                shared.connector.as_ref(),
                shared.config.home_hash_format,
                Some(shared.clone()),
            ).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        request_id = %original_request_id,
                        remote_peer = %remote_peer_id,
                        error = %e,
                        "async delivery: remote connection failed"
                    );
                    return;
                }
            };

        // Class G / F-WB28: connection is multiplexed; concurrent dispatches
        // proceed without serializing on per-connection state. No outer lock.

        // Send the delivery as an authenticated EXECUTE to the remote inbox
        let resource = entity_capability::ResourceTarget {
            targets: vec![deliver_to.uri.clone()],
            exclude: vec![],
        };

        // Async inbox delivery rides the connection grant (the deliver_token
        // is the authority here) — not a continuation cross-peer dispatch, so
        // no scoped dispatch_capability override and no chain bundle.
        let no_chain = std::collections::HashMap::new();
        match crate::remote::send_execute(
            conn.as_ref(),
            &shared.keypair,
            &deliver_to.uri,
            &deliver_to.operation,
            &delivery_entity,
            Some(&resource),
            None, // delivery dispatch — no nested deliver_to
            None, // no scoped dispatch_capability override
            &no_chain,
        )
        .await
        {
            Ok(resp) => {
                tracing::debug!(
                    request_id = %original_request_id,
                    remote_peer = %remote_peer_id,
                    status = resp.status,
                    "async delivery: remote delivery completed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    request_id = %original_request_id,
                    remote_peer = %remote_peer_id,
                    error = %e,
                    "async delivery: remote delivery failed, removing pooled connection"
                );
                shared.remote.remove(&remote_peer_id);
            }
        }
    } else {
        // Local delivery: dispatch through internal execute_fn
        let opts = ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![deliver_to.uri.clone()],
                exclude: vec![],
            }),
            request_id: Some(format!("dlv-{}", original_request_id)),
            ..Default::default()
        };

        tracing::debug!(
            request_id = %original_request_id,
            deliver_uri = %deliver_to.uri,
            deliver_operation = %deliver_to.operation,
            "async delivery: local delivery to inbox"
        );

        match execute_fn(
            "system/inbox".to_string(),
            deliver_to.operation.clone(),
            delivery_entity,
            opts,
        )
        .await
        {
            Ok(r) => {
                tracing::debug!(
                    request_id = %original_request_id,
                    status = r.status,
                    "async delivery: inbox delivery completed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    request_id = %original_request_id,
                    error = %e,
                    "async delivery: inbox delivery failed"
                );
            }
        }
    }
}

/// Write-ahead persist the originating EXECUTE into the local inbox namespace
/// at `(author, request_id)` so a downstream `(author, request_id)` lookup
/// can find it (EXTENSION-DURABILITY §6 / Scenario 5). Mirrors Go's `preserveDurableRequest`
/// in `core/protocol/durability.go`. Best-effort: returns `false` on store
/// failure so the dispatcher can downgrade `applied` observably rather than
/// overclaim (EXTENSION-DURABILITY §5 invariant).
fn preserve_durable_request(
    execute_entity: &entity_entity::Entity,
    request_id: &str,
    shared: &Arc<PeerShared>,
) -> Option<String> {
    if request_id.is_empty() {
        return None;
    }
    let hash = match shared.content_store.put(execute_entity.clone()) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(
                request_id = %request_id,
                error = %e,
                "durability: content store put failed"
            );
            return None;
        }
    };
    let path = format!(
        "/{}/system/inbox/{}",
        shared.keypair.peer_id().as_str(),
        request_id
    );
    shared.location_index.set(&path, hash);
    tracing::debug!(
        request_id = %request_id,
        path = %path,
        hash = %hash,
        "durability: preserved originating EXECUTE in inbox namespace"
    );
    Some(path)
}

/// Build a 202 Accepted response for async delivery acknowledgement (INBOX spec §4.5).
pub fn build_202_response(
    request_id: &str,
    durability_cbor: Option<Vec<u8>>,
) -> Result<Envelope, entity_protocol::ProtocolError> {
    let null_entity = entity_entity::Entity {
        entity_type: "primitive/null".to_string(),
        data: vec![0xf6], // CBOR null
        content_hash: entity_hash::Hash::compute("primitive/null", &[0xf6]),
    };
    build_execute_response_full(request_id, 202, null_entity, HashMap::new(), durability_cbor)
}

/// Build an ExecuteFn closure for handler-to-handler dispatch.
///
/// The closure captures PeerShared and resolves + dispatches to handlers.
/// Internal dispatch inherits the parent's author/capability context.
/// Dispatch a tree-only handler — `resolved.handler` is `None`, but the tree
/// has a `system/handler` manifest at `resolved.pattern`. Per V7 §6.6 the
/// manifest's `expression_path` field is the entity-native dispatch target.
///
/// §7.1 fail-closed: handler grant MUST be present and non-empty before
/// invoking the evaluator — otherwise the expression would run with no
/// capability ceiling.
///
/// If the manifest has no `expression_path`, dispatch fails 404 — the manifest
/// is malformed (per V7 §3.7 `expression_path` is the only entry point an
/// installed-but-uncompiled handler has).
#[cfg(feature = "compute")]
async fn dispatch_tree_only_handler(
    resolved: &entity_handler::ResolvedHandler,
    ctx: &HandlerContext,
    shared: Arc<PeerShared>,
) -> Result<entity_handler::HandlerResult, HandlerError> {
    let manifest = match resolved.manifest.as_ref() {
        Some(m) => m,
        None => {
            // Defensive: resolve_handler only returns handler=None when manifest
            // was found in the tree, so this branch shouldn't be reachable.
            return Ok(entity_handler::HandlerResult::error(
                STATUS_NOT_FOUND,
                make_error_response_entity(
                    "handler_not_found",
                    &format!("No handler manifest at {}", resolved.pattern),
                ),
            ));
        }
    };

    let expression_path = match entity_compute::extract_expression_path(manifest) {
        Some(p) => p,
        None => {
            // Tree manifest exists but declares no implementation. Compiled
            // code would have been required for this pattern; return 404 so
            // callers see the same shape as a missing handler.
            return Ok(entity_handler::HandlerResult::error(
                STATUS_NOT_FOUND,
                make_error_response_entity(
                    "handler_not_found",
                    &format!(
                        "Manifest at {} declares no expression_path and has no compiled implementation",
                        resolved.pattern
                    ),
                ),
            ));
        }
    };

    // §7.1 (CRITICAL): handler grant MUST be present (and validated by
    // load_local_handler_grant) before invoking the evaluator. Without this,
    // the expression would run with no capability ceiling — equivalent to
    // escalation.
    //
    // §S3: empty `grants` is valid — a pure-functional handler (no impure
    // authority) is a registered handler. The expression runs; per-op
    // capability checks (lookup/tree, apply, store) fail naturally because
    // an empty scope covers nothing. Distinct from a missing/invalid grant,
    // which is fail-closed here.
    let grant = match ctx.handler_grant.as_ref() {
        Some(g) => g,
        None => {
            // v1.19 canonical 403 code — single rule per EXTENSION-CONTINUATION
            // §3.10.5 (`{reason}` = `result.data.code` verbatim).
            return Ok(entity_handler::HandlerResult::error(
                STATUS_FORBIDDEN,
                make_error_response_entity(
                    "capability_denied",
                    &format!(
                        "Entity-native handler at {} has no usable handler grant",
                        resolved.pattern
                    ),
                ),
            ));
        }
    };

    // PROPOSAL §4 (E3): bare-primitive results from the evaluator are wrapped
    // at the dispatch boundary using the operation's declared output_type.
    // Look up the type from the handler's interface entity now so the unwrap
    // path can apply it. Defaults to `primitive/any` when absent.
    let output_type = lookup_operation_output_type(
        manifest,
        &ctx.operation,
        shared.content_store.as_ref(),
        shared.location_index.as_ref(),
        shared.keypair.peer_id().as_str(),
    );

    tracing::debug!(
        pattern = %resolved.pattern,
        expression_path = %expression_path,
        output_type = ?output_type,
        "entity-native dispatch"
    );

    entity_compute::dispatch_entity_native(
        &expression_path,
        grant,
        shared.content_store.clone(),
        shared.location_index.clone(),
        shared.keypair.peer_id().as_str(),
        ctx,
        output_type.as_deref(),
    )
}

/// Look up `operations[op].output_type` on the handler's interface entity.
/// Returns `None` when the manifest has no interface ref, the interface entity
/// is missing, or the operation/output_type field isn't declared.
#[cfg(feature = "compute")]
fn lookup_operation_output_type(
    manifest: &entity_entity::Entity,
    operation: &str,
    content_store: &dyn entity_store::ContentStore,
    location_index: &dyn entity_store::LocationIndex,
    local_peer_id: &str,
) -> Option<String> {
    use entity_ecf::ValueExt;
    let data: ciborium::Value =
        ciborium::from_reader(manifest.data.as_slice()).ok()?;
    let interface_path = data.get("interface").and_then(|v| v.as_text())?;
    let qualified = if interface_path.starts_with('/') {
        interface_path.to_string()
    } else {
        format!("/{}/{}", local_peer_id, interface_path)
    };
    let iface_hash = location_index.get(&qualified)?;
    let iface = content_store.get(&iface_hash)?;
    let iface_data: ciborium::Value =
        ciborium::from_reader(iface.data.as_slice()).ok()?;
    let operations = iface_data.get("operations")?;
    let op_spec = operations.get(operation)?;
    op_spec
        .get("output_type")
        .and_then(|v| v.as_text())
        .map(String::from)
}

/// Build a minimal error entity for entity-native dispatch fail-closed paths.
#[cfg(feature = "compute")]
fn make_error_response_entity(code: &str, message: &str) -> entity_entity::Entity {
    let data = entity_ecf::cbor_map! {
        "code" => entity_ecf::text(code),
        "message" => entity_ecf::text(message)
    };
    entity_entity::Entity::new("compute/error", entity_ecf::to_ecf(&data))
        .expect("error entity")
}

/// Path under which `create_handler_grant` binds a handler grant in the tree
/// (`system/capability/grants/{pattern}`). The grant's signature lives
/// separately at the §3.5 invariant-pointer path `system/signature/{grant_hash}`
/// (v7.74 §3.4 CONVERGENT ruling; see [`entity_hash::invariant_signature_path`])
/// — looked up from the grant's content hash at dispatch, not from the pattern.
fn handler_grant_path(local_pid: &str, bare_pattern: &str) -> String {
    format!("/{}/system/capability/grants/{}", local_pid, bare_pattern)
}

/// Load and validate a handler grant from the tree.
///
/// V7 §6.2 + §6.8 + spec-gap-handler-grant-authority §S2/§S3 enforcement:
///
/// - **§S2(a) granter equality.** Cross-peer subtree transfer (revision pull,
///   manual import) drags foreign-issued grants along; we MUST NOT honor
///   them. Direct equality check on `granter` against the local peer's
///   identity hash.
/// - **§S2(b) signature verification.** The signature entity is stored at a
///   sibling tree path by `create_handler_grant` and verified here against
///   the local peer's pubkey. Without this, an attacker with path-write
///   capability could craft a grant carrying `granter = local_identity_hash`
///   that was never actually issued by the peer.
/// - **§S2(c) temporal validity.** `not_before` and `expires_at` are
///   honored — grants in the future or past are rejected.
/// - **§S3 empty grants are valid.** A pure-functional handler may have no
///   impure authority; per-op cap checks fail naturally for impure ops.
///   This function neither asserts nor rejects on `grants.is_empty()` — that
///   policy lives one level up at the dispatch site.
///
/// On any check failure, returns `(None, None)` and logs at warn level so
/// the dispatcher fails closed: entity-native dispatch returns 403, compiled
/// handlers receive `None` in `HandlerContext.handler_grant`.
fn load_local_handler_grant(
    bare_pattern: &str,
    location_index: &dyn entity_store::LocationIndex,
    content_store: &dyn entity_store::ContentStore,
    local_pid: &str,
    local_identity_hash: entity_hash::Hash,
    local_key_type: entity_crypto::KeyType,
    local_pubkey: &[u8],
) -> (
    Option<entity_capability::CapabilityToken>,
    Option<entity_hash::Hash>,
) {
    let grant_path = handler_grant_path(local_pid, bare_pattern);
    let cap_hash = match location_index.get(&grant_path) {
        Some(h) => h,
        None => return (None, None),
    };
    let cap_entity = match content_store.get(&cap_hash) {
        Some(e) => e,
        None => return (None, None),
    };
    let token = match entity_capability::CapabilityToken::from_entity(&cap_entity) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(grant_path = %grant_path, error = %e, "handler grant decode failed");
            return (None, None);
        }
    };

    // §S2(a): granter equality. Cheapest check, runs first.
    // Handler self-grants are always single-sig; multi-sig granters are
    // unexpected here (handler bootstrap doesn't issue multi-sig caps).
    let token_granter_single = match &token.granter {
        entity_capability::Granter::Single(h) => *h,
        entity_capability::Granter::Multi(_) => {
            tracing::warn!(
                grant_path = %grant_path,
                "handler grant rejected: multi-sig granter on handler self-grant"
            );
            return (None, None);
        }
    };
    if token_granter_single != local_identity_hash {
        tracing::warn!(
            grant_path = %grant_path,
            granter = %token_granter_single,
            local = %local_identity_hash,
            "handler grant rejected: granter is not the local peer (§S2)"
        );
        return (None, None);
    }

    // §S2(c): temporal validity. `created_at` is informational; the gates
    // are `not_before` (future) and `expires_at` (past). Both are optional.
    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if let Some(nb) = token.not_before {
        if now_ms < nb {
            tracing::warn!(
                grant_path = %grant_path,
                not_before = nb, now = now_ms,
                "handler grant rejected: not yet valid (§S2)"
            );
            return (None, None);
        }
    }
    if let Some(exp) = token.expires_at {
        if now_ms >= exp {
            tracing::warn!(
                grant_path = %grant_path,
                expires_at = exp, now = now_ms,
                "handler grant rejected: expired (§S2)"
            );
            return (None, None);
        }
    }

    // §S2(b): signature verification. v7.74 §3.4: the sig is bound at the
    // §3.5 invariant-pointer path `system/signature/{grant_hash}`, keyed by
    // this grant's content hash — without it we can't distinguish a
    // peer-issued grant from one a path-write attacker forged.
    let sig_path = entity_hash::invariant_signature_path(local_pid, &cap_hash);
    let sig_hash = match location_index.get(&sig_path) {
        Some(h) => h,
        None => {
            tracing::warn!(
                grant_path = %grant_path, sig_path = %sig_path,
                "handler grant rejected: signature missing (§S2)"
            );
            return (None, None);
        }
    };
    let sig_entity = match content_store.get(&sig_hash) {
        Some(e) => e,
        None => {
            tracing::warn!(
                grant_path = %grant_path, sig_hash = %sig_hash,
                "handler grant rejected: signature entity missing from store (§S2)"
            );
            return (None, None);
        }
    };
    let sig_data = match entity_types::SignatureData::from_entity(&sig_entity) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(grant_path = %grant_path, error = %e, "handler grant rejected: signature decode failed (§S2)");
            return (None, None);
        }
    };
    if sig_data.target != cap_hash {
        tracing::warn!(
            grant_path = %grant_path,
            sig_target = %sig_data.target,
            cap_hash = %cap_hash,
            "handler grant rejected: signature does not target this grant (§S2)"
        );
        return (None, None);
    }
    if sig_data.signer != local_identity_hash {
        tracing::warn!(
            grant_path = %grant_path,
            signer = %sig_data.signer,
            "handler grant rejected: signer is not the local peer (§S2)"
        );
        return (None, None);
    }
    if entity_crypto::verify_for_key_type(
        local_key_type,
        local_pubkey,
        &cap_hash.to_bytes(),
        &sig_data.signature,
    )
    .is_err()
    {
        tracing::warn!(
            grant_path = %grant_path,
            "handler grant rejected: signature verification failed (§S2)"
        );
        return (None, None);
    }

    (Some(token), Some(cap_hash))
}

pub fn make_execute_fn(
    shared: Arc<PeerShared>,
    author: Option<entity_hash::Hash>,
    included: HashMap<entity_hash::Hash, entity_entity::Entity>,
    parent_bounds: Option<entity_handler::Bounds>,
    parent_caller_capability: Option<entity_capability::CapabilityToken>,
) -> ExecuteFn {
    Arc::new(move |handler_path: String, operation: String, params: entity_entity::Entity, opts: ExecuteOptions| {
        let shared = shared.clone();
        let author = author;
        let mut included = included.clone();
        let parent_bounds = parent_bounds.clone();
        // §6.13(b) seam: fold any explicit `opts.included` authority chain
        // into the dispatch's included set at a single point so BOTH the
        // remote branch (merged into the outbound envelope's `included` via
        // `chain_bundle`) and the local branch (threaded into the child
        // context's `included`) carry it. Used when the chain rides in-band
        // (GUIDE-CONFORMANCE §7a.2a) rather than in the local store, where
        // `collect_chain_bundle` cannot reach it. Content-addressed dedup —
        // entries already present are not duplicated; empty for ordinary
        // dispatch (no behavior change).
        for ent in &opts.included {
            included.entry(ent.content_hash).or_insert_with(|| ent.clone());
        }
        // V7 §6.8 / proposal §6.2: caller_capability propagates unchanged through
        // sub-dispatch chains so history transitions record the original external
        // caller, not the intermediate handler.
        let parent_caller_capability = parent_caller_capability.clone();
        Box::pin(async move {
            let local_pid = shared.keypair.peer_id();
            let is_remote = crate::remote::is_remote_uri(&handler_path, local_pid.as_str());

            tracing::debug!(
                handler_path = %handler_path,
                operation = %operation,
                params_type = %params.entity_type,
                remote = is_remote,
                "internal dispatch"
            );

            // --- Remote dispatch: send EXECUTE to remote peer ---
            if is_remote {
                let remote_peer_id = crate::remote::extract_peer_id_from_uri(&handler_path)
                    .ok_or_else(|| HandlerError::Internal(format!(
                        "cannot extract peer_id from remote URI: {}", handler_path
                    )))?;

                let conn: std::sync::Arc<dyn crate::remote::RemoteEndpoint> =
                    crate::remote::get_or_connect(
                        &shared.remote,
                        &remote_peer_id,
                        &shared.keypair,
                        shared.content_store.as_ref(),
                        shared.location_index.as_ref(),
                        local_pid.as_str(),
                        shared.connector.as_ref(),
                shared.config.home_hash_format,
                        // §6.11(b): if this connection has to be freshly
                        // dialed, give its reader a reentry dispatch context
                        // so deliveries the remote pushes back reach us.
                        Some(shared.clone()),
                    ).await.map_err(|e| HandlerError::Internal(format!(
                        "remote connection to {}: {}", remote_peer_id, e
                    )))?;

                // Class G / F-WB28: multiplexed connection — no per-conn lock.
                // Concurrent dispatches proceed via per-request oneshot demux.

                let resource = opts.resource.as_ref();

                // Per CONTINUATION §3.5 step 4 + INBOX §4.5: if deliver_to is set,
                // include it on the wire EXECUTE so the remote peer handles delivery
                // asynchronously (returns 202, delivers result to inbox directly).
                // generate_internal_deliver_token is implementation-defined (§8.4).
                // We generate a scoped token after handshake since INBOX §5.1
                // requires grantee = remote peer identity.
                let deliver_to_params = if let Some(ref dt) = opts.deliver_to {
                    match crate::remote::generate_deliver_token(
                        &shared.keypair,
                        conn.remote_identity_hash(),
                        &dt.uri,
                        &dt.operation,
                    ) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            tracing::warn!(
                                deliver_uri = %dt.uri,
                                error = %e,
                                "internal dispatch: failed to generate deliver_token, falling back to sync"
                            );
                            None
                        }
                    }
                } else {
                    None
                };

                // EXTENSION-CONTINUATION §3.6 step 5 / §4.2 case 3 / §4.3:
                // a continuation dispatch carries its scoped
                // `dispatch_capability` (opts.capability) as the EXECUTE
                // capability — never a silent fallback to the broad
                // connection grant (V7 §6.8 — the cross-peer silent-
                // escalation Amendment-2's recipe step 2 forbids). Its full
                // authority chain (persisted locally at install, §3.2 step 5)
                // is bundled into the dispatched envelope's `included` so the
                // verifying peer can validate it to a root it recognizes
                // (§4.3 chain transport — the general V7 §3.1/§3.2 rule
                // places only the leaf). Ordinary internal dispatch (no
                // opts.capability) is unchanged: None + empty bundle.
                let empty_bundle = std::collections::HashMap::new();
                let (dispatch_cap, mut chain_bundle) = match opts.capability.as_ref() {
                    Some(cap) => match entity_protocol::collect_chain_bundle(
                        &cap.content_hash,
                        |h| shared.content_store.get(h),
                        |p| shared.location_index.get(p),
                    ) {
                        Ok(bundle) => (Some(cap), bundle),
                        Err(e) => {
                            // Chain not fully resolvable locally (unexpected —
                            // install persists it per §3.2 step 5). Send the
                            // scoped leaf cap anyway; B fails closed on its
                            // VerifyChain. That is safe and conformant — we
                            // never substitute the connection grant, so this
                            // is not a §6.8 escalation.
                            tracing::warn!(
                                cap = %cap.content_hash,
                                error = %e,
                                "continuation dispatch: authority chain \
                                 unresolvable; sending scoped leaf cap only"
                            );
                            (Some(cap), std::collections::HashMap::new())
                        }
                    },
                    None => (None, empty_bundle),
                };

                // V7 §3.3 v7.51: request-side envelope-`included` preservation.
                // When an internal sub-dispatch is forwarded to a remote peer,
                // the parent envelope's `included` map MUST travel with the
                // forwarded EXECUTE — otherwise downstream continuations
                // (e.g. EXTENSION-CONTINUATION `deref_included` over an
                // `include_payload`-bundled entity) cannot resolve hash refs
                // the parent put there. Merge into the existing extra-included
                // bundle (envelope.include dedupes on hash, so capability-chain
                // entries already present are not duplicated).
                for (h, ent) in included.iter() {
                    chain_bundle.entry(*h).or_insert_with(|| ent.clone());
                }

                let resp = match crate::remote::send_execute(
                    conn.as_ref(),
                    &shared.keypair,
                    &handler_path,
                    &operation,
                    &params,
                    resource,
                    deliver_to_params.as_ref(),
                    dispatch_cap,
                    &chain_bundle,
                ).await {
                    Ok(r) => r,
                    Err(e) => {
                        // Connection is likely broken — remove from pool
                        shared.remote.remove(&remote_peer_id);
                        return Err(HandlerError::Internal(format!(
                            "remote execute to {}: {}", remote_peer_id, e
                        )));
                    }
                };

                tracing::debug!(
                    handler_path = %handler_path,
                    remote_peer = %remote_peer_id,
                    status = resp.status,
                    has_deliver_to = opts.deliver_to.is_some(),
                    "internal dispatch: remote completed"
                );

                return Ok(entity_handler::HandlerResult {
                    status: resp.status,
                    result: resp.result,
                    // PROPOSAL §2: thread envelope.included from the
                    // remote response back into the HandlerResult so
                    // internal callers see the same subtree an external
                    // caller would have seen.
                    included: resp.included,
                });
            }

            // --- Local dispatch ---
            // V1: Normalize, validate, and qualify handler path (R12)
            let bare = EntityUri::extract_handler_path(&handler_path);
            EntityUri::validate_path_input(bare)
                .map_err(|msg| HandlerError::InvalidParams(msg))?;
            let qualified = EntityUri::qualify_path(bare, local_pid.as_str());
            EntityUri::validate_absolute_path(&qualified)
                .map_err(|msg| HandlerError::InvalidParams(msg))?;

            // Resolve handler
            //
            // R2 (INBOX §3.6 option 3): local-dispatch
            // missing-handler returns the same shape as the wire-dispatch
            // missing-handler path at `dispatch_envelope` (see line ~485) —
            // 404 sync `HandlerResult` carrying a `system/protocol/error`
            // entity with `code: "handler_not_found"`. Previously this site
            // produced `Err(HandlerError::Internal("no handler for: <path>"))`,
            // which the SDK boundary flattened to `SdkError::HandlerError(_)`
            // — losing both the 404 status and the substrate code. The
            // VERIFICATION-R2 memo confirmed the wire path was conformant;
            // this aligns the local path so internal callers (SDK
            // `dispatch_execute`, recursive sub-dispatch) see the same
            // 4xx-bearing HandlerResult an external caller would.
            let resolved = match entity_handler::resolve_handler(
                &qualified,
                shared.content_store.as_ref(),
                shared.location_index.as_ref(),
                &shared.handler_registry,
            ) {
                Some(r) => r,
                None => {
                    tracing::warn!(handler_path = %handler_path, "internal dispatch: no handler found");
                    return Ok(entity_handler::HandlerResult::error(
                        entity_handler::STATUS_NOT_FOUND,
                        entity_handler::error_entity(
                            "handler_not_found",
                            &format!("no handler for path: {}", handler_path),
                        ),
                    ));
                }
            };

            tracing::debug!(
                handler = %resolved_handler_name(&resolved),
                pattern = %resolved.pattern,
                operation = %operation,
                compiled = resolved.handler.is_some(),
                "internal dispatch: handler resolved"
            );

            // Build a synthetic EXECUTE entity for the child context.
            // Per spec §3.4, params is an inline entity {content_hash, data, type}.
            let params_data_val: entity_ecf::Value =
                ciborium::from_reader(params.data.as_slice())
                    .unwrap_or(entity_ecf::Value::Null);
            let params_entity_val = entity_ecf::Value::Map(vec![
                (entity_ecf::text("content_hash"), entity_ecf::Value::Bytes(params.content_hash.to_bytes().to_vec())),
                (entity_ecf::text("data"), params_data_val),
                (entity_ecf::text("type"), entity_ecf::text(&params.entity_type)),
            ]);
            let execute_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("operation"), entity_ecf::text(&operation)),
                (entity_ecf::text("params"), params_entity_val),
                (entity_ecf::text("request_id"), entity_ecf::text("internal")),
                (entity_ecf::text("uri"), entity_ecf::text(&handler_path)),
            ]));
            let execute = entity_entity::Entity::new(entity_types::TYPE_EXECUTE, execute_data)
                .map_err(|e| HandlerError::Internal(e.to_string()))?;

            // V2: Qualify and validate resource targets (R12)
            let resource_target = match opts.resource {
                Some(mut rt) => {
                    let pid = shared.keypair.peer_id();
                    let mut qualified = Vec::with_capacity(rt.targets.len());
                    for t in &rt.targets {
                        EntityUri::validate_path_input(t)
                            .map_err(|msg| HandlerError::InvalidParams(msg))?;
                        let q = EntityUri::qualify_path(t, pid.as_str());
                        if !q.contains('*') {
                            EntityUri::validate_absolute_path(&q)
                                .map_err(|msg| HandlerError::InvalidParams(msg))?;
                        }
                        qualified.push(q);
                    }
                    rt.targets = qualified;
                    Some(rt)
                }
                None => None,
            };
            let request_id = opts.request_id.unwrap_or_else(|| "internal".to_string());

            // Bounds: explicit override from opts, or decrement parent bounds (§5.9)
            let child_bounds = if let Some(b) = opts.bounds {
                Some(b)
            } else if let Some(ref pb) = parent_bounds {
                match pb.decrement() {
                    Ok(b) => Some(b),
                    Err(_) => {
                        return Err(HandlerError::Internal("ttl_exhausted".to_string()));
                    }
                }
            } else {
                None
            };

            // Build child context — params entity passed directly (already parsed)
            let child_execute_fn = make_execute_fn(
                shared.clone(),
                author,
                included.clone(),
                child_bounds.clone(),
                parent_caller_capability.clone(),
            );

            // Load + validate child handler's grant from tree (§6.8, §S2/§S3).
            // Same check ladder as the wire dispatch path —
            // see load_local_handler_grant.
            let child_bare = entity_entity::EntityUri::strip_peer_prefix(&resolved.pattern);
            let (child_handler_grant, child_grant_hash) = load_local_handler_grant(
                &child_bare,
                shared.location_index.as_ref(),
                shared.content_store.as_ref(),
                local_pid.as_str(),
                shared.identity_hash,
                shared.keypair.key_type(),
                &shared.keypair.public_key_bytes(),
            );

            let log_name = resolved_handler_name(&resolved).to_string();

            // V7 §6.8 / proposal §6.2: caller_capability propagates from the
            // outer dispatch context so history records the original external
            // caller. Internal dispatch — matching_grant intentionally absent
            // (no capability constraints); capability_hash intentionally
            // absent (this is sub-dispatch, not a fresh caller-attributable
            // request).
            let mut builder = HandlerContext::builder(execute, params)
                .pattern(resolved.pattern.clone())
                .suffix(resolved.suffix.clone())
                .request_id(request_id.clone())
                .operation(operation.clone())
                .execute_fn(child_execute_fn)
                .included(included.clone());
            if let Some(g) = child_handler_grant {
                builder = builder.handler_grant(g);
            }
            if let Some(c) = parent_caller_capability.clone() {
                builder = builder.caller_capability(c);
            }
            if let Some(rt) = resource_target {
                builder = builder.resource_target(rt);
            }
            if let Some(a) = author {
                builder = builder.author(a);
            }
            if let Some(hgh) = child_grant_hash {
                builder = builder.handler_grant_hash(hgh);
            }
            if let Some(b) = child_bounds {
                builder = builder.bounds(b);
            }
            let ctx = builder.build();

            // EXTENSION-INBOX §4.3 (v5.6, PROPOSAL-CONTENT-INGEST-PASS-THROUGH
            // D1): handler-initiated sub-dispatch with deliver_to
            // MUST follow the same async-spawning semantics as a wire-entry
            // EXECUTE with deliver_to, regardless of whether the target URI is
            // local or remote. Prior to this codification, the local-local
            // case silently dropped deliver_to, breaking any continuation
            // chain whose middle step targeted a local URI.
            //
            // The remote branch above (`if is_remote`) already packs
            // deliver_to into the wire EXECUTE; the wire-entry path on the
            // far side spawns async. The local-local case is what this
            // branch handles.
            if let Some(ref dt) = opts.deliver_to {
                // ExecuteOptions carries entity_handler::DeliverySpec;
                // process_async_delivery expects connection::DeliverySpec.
                // Same shape, distinct types — bridge by field-wise copy.
                let dt = DeliverySpec {
                    uri: dt.uri.clone(),
                    operation: dt.operation.clone(),
                };
                let request_id_for_delivery = request_id.clone();
                let log_name_for_delivery = log_name.clone();
                let shared_for_delivery = shared.clone();
                // Build a fresh execute_fn for the spawned task —
                // process_async_delivery re-dispatches via it. The ctx already
                // owns its own execute_fn for any sub-dispatch the handler
                // initiates; this one is for the delivery routing.
                let delivery_execute_fn = make_execute_fn(
                    shared.clone(),
                    author,
                    included.clone(),
                    None, // bounds reset for the spawned re-dispatch
                    parent_caller_capability.clone(),
                );

                tracing::debug!(
                    handler = %log_name,
                    operation = %operation,
                    request_id = %request_id,
                    deliver_uri = %dt.uri,
                    deliver_operation = %dt.operation,
                    "internal dispatch: deliver_to set, spawning async delivery (D1)"
                );

                crate::runtime::spawn(async move {
                    process_async_delivery(
                        ctx,
                        &dt,
                        &delivery_execute_fn,
                        &request_id_for_delivery,
                        &log_name_for_delivery,
                        shared_for_delivery,
                    )
                    .await;
                });

                // Return 202 Accepted synchronously. The handler runs in the
                // spawned task; its result routes to deliver_to.uri via inbox.
                let accepted = entity_entity::Entity::new(
                    "primitive/null",
                    vec![0xf6], // CBOR null
                )
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
                return Ok(entity_handler::HandlerResult {
                    status: 202,
                    result: accepted,
                    included: std::collections::HashMap::new(),
                });
            }

            // GUIDE-INSPECTABILITY v1.2 §2.1 #3 — internal dispatch is its own
            // dispatcher↔handler-body boundary (peer.execute() / handler-to-
            // handler dispatch). Fire entry + exit hooks symmetric to the wire
            // dispatch site in dispatch_request.
            let internal_target_uri = if ctx.suffix.is_empty() {
                ctx.pattern.clone()
            } else if ctx.pattern.ends_with('/') || ctx.suffix.starts_with('/') {
                format!("{}{}", ctx.pattern, ctx.suffix)
            } else {
                format!("{}/{}", ctx.pattern, ctx.suffix)
            };
            if !shared.dispatch_hooks.is_empty() {
                fire_dispatch_hooks(
                    &shared,
                    &crate::DispatchEvent {
                        target_uri: internal_target_uri.clone(),
                        operation: ctx.operation.clone(),
                        params_hash: ctx.params.content_hash,
                        request_id: ctx.request_id.clone(),
                        timestamp_ms: dispatch_event_timestamp_ms(),
                        phase: crate::DispatchPhase::Entry,
                    },
                );
            }

            // V7 §6.5: compiled handlers take priority; tree-only manifests fall
            // back to entity-native dispatch through the compute evaluator.
            let result = match &resolved.handler {
                Some(handler) => handler.handle(&ctx).await,
                None => {
                    #[cfg(feature = "compute")]
                    {
                        dispatch_tree_only_handler(&resolved, &ctx, shared.clone()).await
                    }
                    #[cfg(not(feature = "compute"))]
                    {
                        Err(HandlerError::Internal(
                            "tree-only handler requires the compute feature".to_string(),
                        ))
                    }
                }
            };

            let (internal_status, internal_response_hash) = match &result {
                Ok(r) => (r.status, r.result.content_hash),
                Err(e) => (
                    match e {
                        HandlerError::InvalidParams(_) => STATUS_BAD_REQUEST,
                        HandlerError::NotSupported(_) => STATUS_NOT_SUPPORTED,
                        HandlerError::Internal(_) => STATUS_INTERNAL_ERROR,
                    },
                    entity_hash::Hash::zero(),
                ),
            };
            if !shared.dispatch_hooks.is_empty() {
                fire_dispatch_hooks(
                    &shared,
                    &crate::DispatchEvent {
                        target_uri: internal_target_uri,
                        operation: ctx.operation.clone(),
                        params_hash: ctx.params.content_hash,
                        request_id: ctx.request_id.clone(),
                        timestamp_ms: dispatch_event_timestamp_ms(),
                        phase: crate::DispatchPhase::Exit {
                            status: internal_status,
                            response_hash: internal_response_hash,
                        },
                    },
                );
            }

            match &result {
                Ok(r) => tracing::debug!(
                    handler = %log_name,
                    operation = %operation,
                    request_id = %request_id,
                    status = r.status,
                    result_type = %r.result.entity_type,
                    "internal dispatch: completed"
                ),
                Err(e) => tracing::warn!(
                    handler = %log_name,
                    operation = %operation,
                    request_id = %request_id,
                    error = %e,
                    "internal dispatch: handler error"
                ),
            }
            result
        })
    })
}

/// Extract the params entity from an EXECUTE entity's data (§3.4).
/// Params is an inline entity map {content_hash, data, type}.
fn extract_params_entity(
    execute: &entity_entity::Entity,
) -> entity_entity::Entity {
    let default = || {
        entity_entity::Entity::new("primitive/null", entity_ecf::to_ecf(&entity_ecf::Value::Null))
            .unwrap_or_else(|_| entity_entity::Entity {
                entity_type: "primitive/null".to_string(),
                data: vec![0xf6], // CBOR null
                content_hash: entity_hash::Hash::zero(),
            })
    };

    let value: ciborium::Value = match ciborium::from_reader(execute.data.as_slice()) {
        Ok(v) => v,
        Err(_) => return default(),
    };
    let map = match value.as_map() {
        Some(m) => m,
        None => return default(),
    };

    for (k, v) in map {
        if k.as_text() == Some("params") {
            if let Some(entity_map) = v.as_map() {
                let mut entity_type = String::new();
                let mut entity_data = Vec::new();

                for (ek, ev) in entity_map {
                    match ek.as_text() {
                        Some("type") => entity_type = ev.as_text().unwrap_or("").to_string(),
                        Some("data") => entity_data = entity_ecf::to_ecf(ev),
                        _ => {}
                    }
                }

                if let Ok(e) = entity_entity::Entity::new(&entity_type, entity_data) {
                    return e;
                }
            }
        }
    }
    default()
}

/// Extract resource target from an EXECUTE entity's data (best-effort).
fn extract_resource_target(
    execute: &entity_entity::Entity,
) -> Option<entity_capability::ResourceTarget> {
    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("resource") {
            let resource_map = v.as_map()?;
            let mut targets = Vec::new();
            let mut exclude = Vec::new();
            for (rk, rv) in resource_map {
                match rk.as_text() {
                    Some("targets") => {
                        if let Some(arr) = rv.as_array() {
                            for item in arr {
                                if let Some(s) = item.as_text() {
                                    targets.push(s.to_string());
                                }
                            }
                        }
                    }
                    Some("exclude") => {
                        if let Some(arr) = rv.as_array() {
                            for item in arr {
                                if let Some(s) = item.as_text() {
                                    exclude.push(s.to_string());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if !targets.is_empty() {
                return Some(entity_capability::ResourceTarget { targets, exclude });
            }
        }
    }
    None
}

/// A delivery specification (per spec §3.11: system/delivery-spec).
#[derive(Debug, Clone)]
pub struct DeliverySpec {
    pub uri: String,
    pub operation: String,
}

// ---------------------------------------------------------------------------
// WB-27 / Class B — dispatcher-side `rejected` chain-error marker
//
// EXTENSION-CONTINUATION v1.20 §3.10.3: when the dispatcher refuses an inbound
// EXECUTE on cap-check AND that EXECUTE is a chain dispatch (Bounds.chain_id
// present per §3.10.3 scope), the dispatcher MUST bind a `rejected`-variant
// marker at the v1.20 path scheme + return ErrorData.rejected_marker as the
// mirror pointer per §3.10.4.
//
// Authority per §3.10.7: behavioral, not mechanism. Rust realizes the named
// `core/chain-errors` component-owned authority via direct local-store ops
// (the dispatcher's local-write surface doesn't traverse a cap-check). Same
// runtime mechanism as the continuation engine's `write_lost_error_marker`.
// ---------------------------------------------------------------------------

/// Build a `403 capability_denied` response envelope, binding the rejected-
/// variant chain-error marker on the way out when this is a chain dispatch.
/// Returns the response envelope; the marker hash (when bound) rides on
/// `ErrorData.rejected_marker` per v1.20 §3.10.4.
fn build_capability_denied_response(
    shared: &PeerShared,
    envelope: &Envelope,
    request_id: &str,
    author_hash: &entity_hash::Hash,
    handler_path: &str,
    message: &str,
) -> Envelope {
    let marker_hash = try_bind_rejected_marker(shared, envelope, request_id, author_hash, handler_path);
    entity_protocol::build_error_response_with_marker(
        request_id,
        STATUS_FORBIDDEN,
        "capability_denied",
        message,
        marker_hash,
    )
    .unwrap_or_else(|_| Envelope::new(envelope.root.clone()))
}

/// Bind a rejected-variant marker when the rejected EXECUTE is a chain
/// dispatch. Returns `None` when the EXECUTE doesn't carry a `chain_id`
/// (per §3.10.3 scope — ordinary 403s have no marker) or when the bind
/// itself fails (logged via `tracing::warn!` per §3.10.8).
fn try_bind_rejected_marker(
    shared: &PeerShared,
    envelope: &Envelope,
    request_id: &str,
    author_hash: &entity_hash::Hash,
    handler_path: &str,
) -> Option<entity_hash::Hash> {
    let bounds = extract_bounds(&envelope.root)?;
    let chain_id = bounds.chain_id?;
    if chain_id.is_empty() {
        return None;
    }
    // §3.10.6 timestamp-capture discipline: captured at failure-origination
    // (here — the dispatcher's cap-rejection IS the failure observation).
    let timestamp = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let requesting_peer_id = resolve_author_peer_id(envelope, author_hash);
    let step_index = request_id.to_string();

    // §3.10.6 body fields (rejected kind): reason, timestamp, chain_id,
    // step_index, requesting_peer_id, attempted_uri.
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("attempted_uri"), entity_ecf::text(handler_path)),
        (entity_ecf::text("chain_id"), entity_ecf::text(&chain_id)),
        (entity_ecf::text("reason"), entity_ecf::text("capability_denied")),
        (
            entity_ecf::text("requesting_peer_id"),
            entity_ecf::text(&requesting_peer_id),
        ),
        (entity_ecf::text("step_index"), entity_ecf::text(&step_index)),
        (
            entity_ecf::text("timestamp"),
            entity_ecf::integer(timestamp as i64),
        ),
    ]));
    let entity = match entity_entity::Entity::new("system/runtime/chain-error-lost", data) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "WB-27: rejected-marker entity build FAILED");
            return None;
        }
    };
    let marker_hash = entity.content_hash;
    let marker_path = format!(
        "/{}/system/runtime/chain-errors/rejected/{}/{}/capability_denied/{}",
        shared.peer_id.as_str(),
        chain_id,
        step_index,
        marker_hash.to_hex(),
    );
    match shared.content_store.put(entity) {
        Ok(h) => {
            shared.location_index.set(&marker_path, h);
            Some(marker_hash)
        }
        Err(e) => {
            // §3.10.8 bind failure visibility.
            tracing::warn!(
                path = %marker_path,
                error = %e,
                "WB-27: rejected-marker store put FAILED",
            );
            None
        }
    }
}

/// Look up the author's peer_id (base58) from envelope.included by author
/// content hash. Falls back to the hash's hex form when the identity isn't
/// in the envelope — marker is informational so a fallback is fine.
fn resolve_author_peer_id(envelope: &Envelope, author_hash: &entity_hash::Hash) -> String {
    if let Some(identity) = envelope.find_included(author_hash) {
        if let Ok(v) = ciborium::from_reader::<ciborium::Value, _>(identity.data.as_slice()) {
            if let Some(map) = v.as_map() {
                for (k, val) in map {
                    if k.as_text() == Some("peer_id") {
                        if let Some(s) = val.as_text() {
                            return s.to_string();
                        }
                    }
                }
            }
        }
    }
    author_hash.to_hex()
}

/// Extract bounds from an EXECUTE entity's data (§3.11, §5.9).
///
/// Bounds is an inline entity at the `bounds` key with type `system/bounds`
/// and data containing optional ttl, budget, chain_id, visited.
pub fn extract_bounds(execute: &entity_entity::Entity) -> Option<entity_handler::Bounds> {
    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("bounds") {
            // Bounds is an inline entity {type, data, content_hash}
            // We want the data field decoded as a map
            let bounds_map = v.as_map()?;
            // Find the data field — it's CBOR bytes containing the bounds map
            for (bk, bv) in bounds_map {
                if bk.as_text() == Some("data") {
                    let data_bytes = bv.as_bytes()?;
                    let data_value: ciborium::Value =
                        ciborium::from_reader(data_bytes.as_slice()).ok()?;
                    return decode_bounds_data(&data_value);
                }
            }
            // Fallback: maybe bounds is encoded directly as a map (not inline entity)
            return decode_bounds_data(v);
        }
    }
    None
}

fn decode_bounds_data(value: &ciborium::Value) -> Option<entity_handler::Bounds> {
    let map = value.as_map()?;
    let mut bounds = entity_handler::Bounds::default();
    for (k, v) in map {
        match k.as_text() {
            Some("ttl") => {
                if let Some(i) = v.as_integer() {
                    bounds.ttl = u64::try_from(i).ok();
                }
            }
            Some("budget") => {
                if let Some(i) = v.as_integer() {
                    bounds.budget = u64::try_from(i).ok();
                }
            }
            Some("cascade_depth") => {
                if let Some(i) = v.as_integer() {
                    bounds.cascade_depth = u64::try_from(i).ok();
                }
            }
            Some("chain_id") => {
                if let Some(s) = v.as_text() {
                    bounds.chain_id = Some(s.to_string());
                }
            }
            Some("parent_chain_id") => {
                if let Some(s) = v.as_text() {
                    bounds.parent_chain_id = Some(s.to_string());
                }
            }
            Some("visited") => {
                if let Some(arr) = v.as_array() {
                    bounds.visited = arr
                        .iter()
                        .filter_map(|x| x.as_text().map(|s| s.to_string()))
                        .collect();
                }
            }
            _ => {}
        }
    }
    Some(bounds)
}

/// Extract deliver_to from an EXECUTE entity's data (§3.2).
pub fn extract_deliver_to(execute: &entity_entity::Entity) -> Option<DeliverySpec> {
    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("deliver_to") {
            let dt_map = v.as_map()?;
            let mut uri = None;
            let mut operation = "receive".to_string(); // default per spec
            for (dk, dv) in dt_map {
                match dk.as_text() {
                    Some("uri") => uri = dv.as_text().map(|s| s.to_string()),
                    Some("operation") => {
                        if let Some(s) = dv.as_text() {
                            operation = s.to_string();
                        }
                    }
                    _ => {}
                }
            }
            if let Some(uri) = uri {
                return Some(DeliverySpec { uri, operation });
            }
        }
    }
    None
}

/// Extract deliver_token hash from an EXECUTE entity's data (INBOX spec §2.3).
pub fn extract_deliver_token(execute: &entity_entity::Entity) -> Option<entity_hash::Hash> {
    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("deliver_token") {
            let bytes = v.as_bytes()?;
            return entity_hash::Hash::from_bytes(bytes).ok();
        }
    }
    None
}

/// V7 §4.4 v7.64 dual-form policy-table consultation at handshake time.
/// Resolution order: (1) hex form `system/capability/policy/{caller_peer_hex}`,
/// (2) Base58 form `system/capability/policy/{caller_peer_id_base58}`, (3)
/// `system/capability/policy/default`. The Base58 form is the V7 §3.6
/// v7.65 lazy-canonicalization site — operator may pre-configure a policy
/// using a pasted Base58 handle before any handshake with that peer; the
/// dual-form mechanism resolves it at handshake time when the pubkey
/// becomes available.
///
/// On a Base58-form hit the handler canonicalizes the entry (writes hex,
/// deletes Base58 — V7 §3.6 v7.65 §1117: idempotent via the v7.64
/// self-healing dual-form policy machinery, whose semantic narrows to
/// legacy-decode under v7.65). The `remote_peer_id_base58` passed here is
/// the canonical-form Base58 derived from the now-known pubkey per §1.5
/// v7.65 (Ed25519 → identity-multihash).
///
/// Closeout F8: fallback segment was `*` in v7.62; renamed to the literal
/// `default` to remove the glyph collision with `*`-as-glob.
fn lookup_capability_policy_grants(
    shared: &Arc<PeerShared>,
    remote_identity_hash: &entity_hash::Hash,
    remote_peer_id_base58: &str,
) -> Option<Vec<entity_capability::GrantEntry>> {
    let remote_hex = remote_identity_hash.to_hex();
    let by_hex = format!(
        "/{}/system/capability/policy/{}",
        shared.peer_id, remote_hex
    );
    if let Some(g) = decode_policy_grants_at(shared, &by_hex) {
        return Some(g);
    }
    let by_b58 = format!(
        "/{}/system/capability/policy/{}",
        shared.peer_id, remote_peer_id_base58
    );
    if let Some(g) = decode_policy_grants_at(shared, &by_b58) {
        // V7 §3.6 v7.65 lazy-canonicalization event: rebind under
        // canonical hex form. Idempotent + self-healing — concurrent
        // handshakes race to the same end state.
        if let Some(h) = shared.location_index.get(&by_b58) {
            shared.location_index.set(&by_hex, h);
            shared.location_index.remove(&by_b58);
            tracing::debug!(
                from = %by_b58,
                to = %by_hex,
                "V7 §3.6 v7.65: canonicalized pending-canonicalization \
                 Base58-form policy entry to canonical hex form"
            );
        }
        return Some(g);
    }
    let by_default = format!(
        "/{}/system/capability/policy/{}",
        shared.peer_id,
        entity_capability::POLICY_FALLBACK_SEGMENT
    );
    decode_policy_grants_at(shared, &by_default)
}

fn decode_policy_grants_at(
    shared: &Arc<PeerShared>,
    path: &str,
) -> Option<Vec<entity_capability::GrantEntry>> {
    let h = shared.location_index.get(path)?;
    let entity = shared.content_store.get(&h)?;
    if entity.entity_type != entity_types::TYPE_CAP_POLICY_ENTRY {
        return None;
    }
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("grants") {
            let arr = v.as_array()?;
            let mut out = Vec::with_capacity(arr.len());
            for entry in arr {
                let g = entity_capability::decode_grant_entry(entry).ok()?;
                out.push(g);
            }
            return Some(out);
        }
    }
    None
}

/// Build an EXECUTE_RESPONSE error envelope for a handshake-phase
/// failure, routing the structured inner `ProtocolError` (when present)
/// through `wire_error_code()` so the wire surface matches the V7 §4.7
/// error registry (e.g., `400 unsupported_key_type` for v7.66 §4.4
/// surface 6) rather than collapsing to the generic `default_code`
/// catch-all. `default_code` is used when the error has no registry
/// entry (e.g., decode failures during hello → `"handshake_failed"`).
fn handshake_error_envelope(
    inbound: &Envelope,
    err: &PeerError,
    default_code: &str,
) -> Envelope {
    let request_id = extract_request_id(inbound).unwrap_or_else(|| "unknown".to_string());
    let (status, code, message) = match err {
        PeerError::Protocol(pe) => (
            pe.wire_status_code(),
            pe.wire_error_code().unwrap_or(default_code).to_string(),
            pe.to_string(),
        ),
        PeerError::ConnectionError(s) | PeerError::BuildError(s) => {
            (STATUS_BAD_REQUEST, default_code.to_string(), s.clone())
        }
    };
    build_error_response(&request_id, status, &code, &message)
        .unwrap_or_else(|_| Envelope::new(inbound.root.clone()))
}

/// Extract request_id from an EXECUTE entity's data (best-effort).
fn extract_request_id(envelope: &Envelope) -> Option<String> {
    let value: ciborium::Value = ciborium::from_reader(envelope.root.data.as_slice()).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("request_id") {
            return v.as_text().map(|s| s.to_string());
        }
    }
    None
}
