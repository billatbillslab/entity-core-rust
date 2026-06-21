//! HTTP outbound endpoint (`system/peer/transport/http` profile —
//! EXTENSION-NETWORK §6.5.2c).
//!
//! Sibling of [`crate::remote::RemoteConnection`] (stream-multiplexed
//! TCP / WS / Memory) at the [`RemoteEndpoint`] layer. HTTP is
//! request/response per POST (half-duplex per connection per §6.5.2c
//! Amendment 3/7) — no long-lived byte pipe and no reader-demux task.
//! Each `dispatch_envelope` call does its own POST round-trip.
//!
//! **Session correlation** matches the server's `X-Entity-Session`
//! contract (see `http_live::SESSION_HEADER`): on HELLO POST the
//! server allocates and returns a session id; we capture it and echo
//! it on the AUTHENTICATE POST so the server's `Connection` state
//! machine routes our follow-up envelope to the same allocated state.
//! Post-AUTHENTICATE the server's session is `Established`; further
//! EXECUTEs continue to echo the same id so the server's
//! `dispatch_session_envelope` routes us through the post-handshake
//! `dispatch_request` path (rather than starting a fresh handshake).
//!
//! **Concurrency.** After `connect()` returns, all the fields
//! (`session_id`, `capability`, `auth_included`, etc.) are immutable
//! for the lifetime of the endpoint. `dispatch_envelope` is naturally
//! reentrant — each POST is its own `reqwest` Future, no per-endpoint
//! locking required. This is the structural reason the V7 §6.11 /
//! F-WB28 Class-G deadlock that motivated [`RemoteConnection`]'s
//! multiplexed reader CANNOT recur on HTTP: there is no shared
//! in-flight state between concurrent EXECUTEs on the same endpoint.
//!
//! **Native-only.** WASM does its HTTP outbound through the browser's
//! `fetch()` from `bindings/wasm-worker-host`. Gated `http-live`
//! alongside the server.

#![cfg(all(feature = "http-live", not(target_arch = "wasm32")))]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use entity_crypto::IdentityKeypair;
use entity_entity::{Entity, Envelope};
use entity_hash::Hash;
use entity_wire::{decode_envelope, encode_envelope};

use crate::remote::{DispatchFuture, RemoteEndpoint};
use crate::PeerError;

/// Default per-request HTTP POST timeout. Mirrors the stream
/// transport's `DEFAULT_REQUEST_TIMEOUT` (30s) — independent of the
/// connection-establishment timeout; per-request, not per-endpoint
/// (V7 §6.x transport-reentry contract point (c)).
const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP outbound endpoint to a remote peer. One per pooled peer.
///
/// Holds the post-handshake state captured during [`connect`]:
/// capability token granted by the remote, the `auth_included` map
/// for chain verification, the remote peer's identity, plus the
/// `X-Entity-Session` cookie the remote allocated for our session.
pub struct HttpConnection {
    /// Endpoint URL (`http://host:port/path` per §6.5.2c D4).
    endpoint_url: String,
    /// `reqwest::Client` reused across POSTs (connection pooling +
    /// rustls handshake cache).
    client: reqwest::Client,
    /// Server-allocated session id (X-Entity-Session). Echoed on every
    /// POST after the initial HELLO response.
    session_id: String,
    /// Capability token received during handshake.
    capability: Entity,
    /// All entities from the authenticate-response included map.
    auth_included: HashMap<Hash, Entity>,
    /// Remote peer ID (verified during handshake).
    remote_peer_id: String,
    /// Remote peer's identity entity hash.
    remote_identity_hash: Hash,
    /// Monotonic request counter — atomic so concurrent
    /// `dispatch_envelope` calls get distinct request ids.
    request_seq: AtomicU64,
    /// Closed flag — set when a POST returns a hard error that
    /// invalidates the session (e.g., server-side session eviction).
    /// Polled by [`is_closed`] (currently advisory only; pool prune
    /// would consult).
    closed: Mutex<bool>,
}

impl HttpConnection {
    /// Open an HTTP-live outbound endpoint at `endpoint_url` and run
    /// HELLO + AUTHENTICATE handshakes over two separate POSTs. The
    /// `X-Entity-Session` returned by the server on the HELLO response
    /// is captured and echoed on AUTHENTICATE so the server's
    /// `Connection` state machine advances against the same session.
    pub async fn connect(
        endpoint_url: &str,
        keypair: &IdentityKeypair,
        home_format: u8,
    ) -> Result<Self, PeerError> {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| PeerError::ConnectionError(format!("build http client: {}", e)))?;

        // --- Phase 1: HELLO POST ---
        let mut nonce = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        // §4.5: advertise our negotiation surface.
        let local_hash_formats = entity_protocol::default_advertised_hash_formats(home_format);
        let hello = entity_protocol::HelloData {
            peer_id: keypair.peer_id().to_string(),
            nonce: nonce.clone(),
            protocols: vec!["entity-core/1.0".to_string()],
            hash_formats: local_hash_formats.clone(),
            key_types: entity_protocol::default_advertised_key_types(),
            timestamp: None,
        };
        let hello_entity = hello
            .to_entity()
            .map_err(|e| PeerError::ConnectionError(format!("build hello: {}", e)))?;
        let hello_execute =
            entity_protocol::build_connect_execute("connect-hello", "hello", &hello_entity)
                .map_err(|e| PeerError::ConnectionError(format!("build hello execute: {}", e)))?;
        let hello_envelope = Envelope::new(hello_execute);
        let hello_body = encode_envelope(&hello_envelope);

        let resp = client
            .post(endpoint_url)
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .body(hello_body)
            .send()
            .await
            .map_err(|e| PeerError::ConnectionError(format!("hello POST: {}", e)))?;

        // Capture the server-allocated session id BEFORE consuming the
        // body (the headers are borrowed from the response).
        let session_id = resp
            .headers()
            .get(crate::http_live::SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                PeerError::ConnectionError(format!(
                    "http: server did not return {} header on hello",
                    crate::http_live::SESSION_HEADER
                ))
            })?
            .to_string();

        let resp_status = resp.status();
        let resp_bytes = resp
            .bytes()
            .await
            .map_err(|e| PeerError::ConnectionError(format!("hello body read: {}", e)))?;

        if !resp_status.is_success() {
            return Err(PeerError::ConnectionError(format!(
                "hello POST returned HTTP {}: {}",
                resp_status,
                String::from_utf8_lossy(&resp_bytes)
            )));
        }

        let hello_resp_envelope = decode_envelope(&resp_bytes).map_err(|e| {
            PeerError::ConnectionError(format!("decode hello response: {}", e))
        })?;
        let hello_resp =
            entity_protocol::parse_execute_response(&hello_resp_envelope).map_err(|e| {
                PeerError::ConnectionError(format!("parse hello response: {}", e))
            })?;
        if hello_resp.status != 200 {
            return Err(PeerError::ConnectionError(format!(
                "hello envelope status: {}",
                hello_resp.status
            )));
        }
        let remote_hello = entity_protocol::HelloData::from_entity(&hello_resp.result)
            .map_err(|e| PeerError::ConnectionError(format!("parse remote hello: {}", e)))?;

        // §4.5 initiator-side negotiation: active format = first match in our
        // order that the responder advertised (converges with the responder).
        let active_format = entity_protocol::negotiate_active_format(
            &local_hash_formats,
            &remote_hello.hash_formats,
        )
        .ok_or_else(|| {
            PeerError::ConnectionError("no common content_hash_format with remote peer".into())
        })?;

        let remote_nonce = remote_hello.nonce;
        let remote_peer_id = remote_hello.peer_id;

        // --- Phase 2: AUTHENTICATE POST (authored under §4.5a active format) ---
        let auth_envelope =
            entity_protocol::build_authenticate_envelope(keypair, &remote_nonce, active_format)
                .map_err(|e| PeerError::ConnectionError(format!("build authenticate: {}", e)))?;
        let auth_body = encode_envelope(&auth_envelope);

        let auth_resp = client
            .post(endpoint_url)
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .header(crate::http_live::SESSION_HEADER, &session_id)
            .body(auth_body)
            .send()
            .await
            .map_err(|e| PeerError::ConnectionError(format!("authenticate POST: {}", e)))?;
        let auth_status = auth_resp.status();
        let auth_resp_bytes = auth_resp.bytes().await.map_err(|e| {
            PeerError::ConnectionError(format!("authenticate body read: {}", e))
        })?;
        if !auth_status.is_success() {
            return Err(PeerError::ConnectionError(format!(
                "authenticate POST returned HTTP {}: {}",
                auth_status,
                String::from_utf8_lossy(&auth_resp_bytes)
            )));
        }
        let auth_resp_envelope = decode_envelope(&auth_resp_bytes).map_err(|e| {
            PeerError::ConnectionError(format!("decode auth response: {}", e))
        })?;
        let auth_parsed =
            entity_protocol::parse_execute_response(&auth_resp_envelope).map_err(|e| {
                PeerError::ConnectionError(format!("parse auth response: {}", e))
            })?;
        if auth_parsed.status != 200 {
            return Err(PeerError::ConnectionError(format!(
                "authenticate envelope status: {}",
                auth_parsed.status
            )));
        }

        // Extract the capability token hash from the grant result and
        // resolve to the cap entity in the response's included map.
        let grant_data: ciborium::Value =
            ciborium::from_reader(auth_parsed.result.data.as_slice()).map_err(|e| {
                PeerError::ConnectionError(format!("decode grant: {}", e))
            })?;
        let grant_map = grant_data
            .as_map()
            .ok_or_else(|| PeerError::ConnectionError("grant data not a map".into()))?;
        let mut cap_hash = None;
        for (k, v) in grant_map {
            if k.as_text() == Some("token") {
                if let Some(bytes) = v.as_bytes() {
                    cap_hash = Hash::from_bytes(bytes).ok();
                }
            }
        }
        let cap_hash = cap_hash.ok_or_else(|| {
            PeerError::ConnectionError("no token hash in authenticate response grant".into())
        })?;

        let capability = auth_resp_envelope
            .find_included(&cap_hash)
            .cloned()
            .ok_or_else(|| {
                PeerError::ConnectionError(
                    "capability token entity not in auth response included".into(),
                )
            })?;

        let auth_included: HashMap<Hash, Entity> = auth_resp_envelope
            .included
            .iter()
            .map(|(h, e)| (*h, e.clone()))
            .collect();

        let remote_identity_hash = auth_included
            .values()
            .find(|e| e.entity_type == entity_crypto::TYPE_PEER)
            .map(|e| e.content_hash)
            .unwrap_or(Hash::zero());

        tracing::info!(
            remote_peer = %remote_peer_id,
            endpoint = %endpoint_url,
            session = %session_id,
            "http outbound: handshake complete"
        );

        Ok(Self {
            endpoint_url: endpoint_url.to_string(),
            client,
            session_id,
            capability,
            auth_included,
            remote_peer_id,
            remote_identity_hash,
            request_seq: AtomicU64::new(0),
            closed: Mutex::new(false),
        })
    }
}

impl RemoteEndpoint for HttpConnection {
    fn remote_peer_id(&self) -> &str {
        &self.remote_peer_id
    }
    fn remote_identity_hash(&self) -> Hash {
        self.remote_identity_hash
    }
    fn capability(&self) -> &Entity {
        &self.capability
    }
    fn auth_included(&self) -> &HashMap<Hash, Entity> {
        &self.auth_included
    }
    fn next_request_id(&self) -> String {
        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        format!("http-req-{}", seq)
    }
    fn transport_type(&self) -> &'static str {
        "http"
    }
    fn dispatch_raw<'a>(
        &'a self,
        _request_id: String,
        frame: Vec<u8>,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let body = frame;
            let resp = self
                .client
                .post(&self.endpoint_url)
                .header(reqwest::header::CONTENT_TYPE, "application/cbor")
                .header(crate::http_live::SESSION_HEADER, &self.session_id)
                .body(body)
                .send()
                .await
                .map_err(|e| {
                    *self.closed.lock().unwrap() = true;
                    PeerError::ConnectionError(format!("http EXECUTE POST: {}", e))
                })?;

            let status = resp.status();
            let resp_bytes = resp
                .bytes()
                .await
                .map_err(|e| {
                    PeerError::ConnectionError(format!("http EXECUTE body read: {}", e))
                })?;
            if !status.is_success() {
                return Err(PeerError::ConnectionError(format!(
                    "http EXECUTE returned HTTP {}: {}",
                    status,
                    String::from_utf8_lossy(&resp_bytes)
                )));
            }

            let resp_envelope = decode_envelope(&resp_bytes).map_err(|e| {
                PeerError::ConnectionError(format!("decode EXECUTE response: {}", e))
            })?;
            let parsed =
                entity_protocol::parse_execute_response(&resp_envelope).map_err(|e| {
                    PeerError::ConnectionError(format!("parse EXECUTE response: {}", e))
                })?;
            Ok(parsed)
        })
    }
}
