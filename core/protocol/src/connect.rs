//! Connection handshake logic (§4).
//!
//! Per spec §4.1, handshake messages are EXECUTE/EXECUTE_RESPONSE:
//! - Hello: EXECUTE targeting system/protocol/connect, operation "hello"
//! - Authenticate: EXECUTE targeting system/protocol/connect, operation "authenticate"
//!
//! The hello/authenticate data is the params entity inside the EXECUTE.

use entity_crypto::{verify_for_key_type, IdentityKeypair, KeyType, PeerId};
use entity_entity::{Entity, Envelope, TYPE_SIGNATURE};
use entity_hash::Hash;
use entity_types::{SignatureData, TYPE_AUTHENTICATE, TYPE_EXECUTE, TYPE_HELLO};

use crate::ProtocolError;

/// Connection path — sole pre-authorized path (§4.2).
pub const CONNECT_PATH: &str = "system/protocol/connect";

/// Nonce size in bytes for handshake challenge (§4.3).
const NONCE_SIZE: usize = 32;

/// Connection state machine (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Waiting for hello.
    AwaitingHello,
    /// Hello received, waiting for authenticate.
    AwaitingAuthenticate,
    /// Fully connected.
    Established,
}

/// Parsed hello entity data.
#[derive(Debug, Clone)]
pub struct HelloData {
    pub peer_id: String,
    pub nonce: Vec<u8>,
    pub protocols: Vec<String>,
    /// `content_hash_format` strings (§8.2), preference-ordered. A
    /// **single active value** field (§4.5): the connection's active format
    /// is the first match in the initiator's order. Absent on the wire
    /// defaults to `["ecfv1-sha256"]` (§4.5).
    pub hash_formats: Vec<String>,
    /// `key_type` strings (§3.5), an **accept-set** (§4.5): the set of
    /// key types this peer can verify. Absent on the wire defaults to
    /// `["ed25519"]` (§4.5).
    pub key_types: Vec<String>,
    pub timestamp: Option<u64>,
}

impl HelloData {
    /// Parse hello data from an entity.
    pub fn from_entity(entity: &Entity) -> Result<Self, ProtocolError> {
        if entity.entity_type != TYPE_HELLO {
            return Err(ProtocolError::Invalid(format!(
                "expected {}, got {}",
                TYPE_HELLO, entity.entity_type
            )));
        }

        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| ProtocolError::Invalid(e.to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| ProtocolError::Invalid("hello data must be a map".into()))?;

        let mut peer_id = None;
        let mut nonce = None;
        let mut protocols = Vec::new();
        let mut hash_formats: Option<Vec<String>> = None;
        let mut key_types: Option<Vec<String>> = None;
        let mut timestamp = None;

        let str_array = |v: &ciborium::Value| -> Vec<String> {
            v.as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_text().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };

        for (k, v) in map {
            match k.as_text() {
                Some("peer_id") => peer_id = v.as_text().map(|s| s.to_string()),
                Some("nonce") => nonce = v.as_bytes().map(|b| b.to_vec()),
                Some("protocols") => protocols = str_array(v),
                Some("hash_formats") => hash_formats = Some(str_array(v)),
                Some("key_types") => key_types = Some(str_array(v)),
                Some("timestamp") => {
                    timestamp = v.as_integer().and_then(|i| u64::try_from(i).ok());
                }
                _ => {}
            }
        }

        Ok(HelloData {
            peer_id: peer_id.ok_or(ProtocolError::MissingField("peer_id"))?,
            nonce: nonce.ok_or(ProtocolError::MissingField("nonce"))?,
            protocols,
            // §4.5 defaults when the field is absent on the wire (pre-v7.69
            // peers): hash_formats → ["ecfv1-sha256"], key_types → ["ed25519"].
            hash_formats: hash_formats.unwrap_or_else(|| vec!["ecfv1-sha256".to_string()]),
            key_types: key_types.unwrap_or_else(|| vec!["ed25519".to_string()]),
            timestamp,
        })
    }

    /// Build a hello entity.
    pub fn to_entity(&self) -> Result<Entity, ProtocolError> {
        let mut entries = vec![
            (
                entity_ecf::text("nonce"),
                entity_ecf::Value::Bytes(self.nonce.clone()),
            ),
            (
                entity_ecf::text("peer_id"),
                entity_ecf::text(&self.peer_id),
            ),
        ];

        if !self.protocols.is_empty() {
            let arr: Vec<entity_ecf::Value> =
                self.protocols.iter().map(entity_ecf::text).collect();
            entries.push((
                entity_ecf::text("protocols"),
                entity_ecf::Value::Array(arr),
            ));
        }

        // §4.5 negotiation fields. Emitted in canonical key order (ECF sorts
        // keys, so source order here is irrelevant). Always advertised so a
        // v7.69 peer's preferences are explicit on the wire; a peer that
        // omits them is read with the §4.5 defaults by the receiver.
        if !self.hash_formats.is_empty() {
            let arr: Vec<entity_ecf::Value> =
                self.hash_formats.iter().map(entity_ecf::text).collect();
            entries.push((
                entity_ecf::text("hash_formats"),
                entity_ecf::Value::Array(arr),
            ));
        }
        if !self.key_types.is_empty() {
            let arr: Vec<entity_ecf::Value> =
                self.key_types.iter().map(entity_ecf::text).collect();
            entries.push((
                entity_ecf::text("key_types"),
                entity_ecf::Value::Array(arr),
            ));
        }

        if let Some(ts) = self.timestamp {
            entries.push((
                entity_ecf::text("timestamp"),
                entity_ecf::integer(ts as i64),
            ));
        }

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(entries));
        Entity::new(TYPE_HELLO, data).map_err(|e| ProtocolError::Invalid(e.to_string()))
    }
}

/// Parsed authenticate entity data.
#[derive(Debug, Clone)]
pub struct AuthenticateData {
    pub peer_id: String,
    pub public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_type: String,
}

impl AuthenticateData {
    /// Parse authenticate data from an entity.
    pub fn from_entity(entity: &Entity) -> Result<Self, ProtocolError> {
        if entity.entity_type != TYPE_AUTHENTICATE {
            return Err(ProtocolError::Invalid(format!(
                "expected {}, got {}",
                TYPE_AUTHENTICATE, entity.entity_type
            )));
        }

        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| ProtocolError::Invalid(e.to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| ProtocolError::Invalid("authenticate data must be a map".into()))?;

        let mut peer_id = None;
        let mut public_key = None;
        let mut nonce = None;
        let mut key_type = None;

        for (k, v) in map {
            match k.as_text() {
                Some("peer_id") => peer_id = v.as_text().map(|s| s.to_string()),
                Some("public_key") => public_key = v.as_bytes().map(|b| b.to_vec()),
                Some("nonce") => nonce = v.as_bytes().map(|b| b.to_vec()),
                Some("key_type") => key_type = v.as_text().map(|s| s.to_string()),
                _ => {}
            }
        }

        Ok(AuthenticateData {
            peer_id: peer_id.ok_or(ProtocolError::MissingField("peer_id"))?,
            public_key: public_key.ok_or(ProtocolError::MissingField("public_key"))?,
            nonce: nonce.ok_or(ProtocolError::MissingField("nonce"))?,
            key_type: key_type.unwrap_or_else(|| "ed25519".to_string()),
        })
    }
}

/// Default advertised `hash_formats` for a peer whose home authoring
/// format is `home_format` (§4.5). A peer SHOULD advertise every format it
/// supports (§4.5a); a SHA-384 home peer advertises SHA-384 first (its
/// preference) then SHA-256 (the floor it can negotiate down to), so it
/// interoperates with SHA-256-only peers. A SHA-256 home peer advertises
/// only the floor.
pub fn default_advertised_hash_formats(home_format: u8) -> Vec<String> {
    match home_format {
        entity_hash::HASH_ALGORITHM_SHA384 => {
            vec!["ecfv1-sha384".to_string(), "ecfv1-sha256".to_string()]
        }
        _ => vec!["ecfv1-sha256".to_string()],
    }
}

/// Default advertised `key_types` accept-set (§4.5). This peer can verify
/// signatures from either allocated production key type; each peer signs
/// with the one its own identity holds.
pub fn default_advertised_key_types() -> Vec<String> {
    vec!["ed25519".to_string(), "ed448".to_string()]
}

/// §4.5 single-active-value negotiation: the active `content_hash_format`
/// is the first entry in the **initiator's** preference order that the
/// **responder** also supports, mapped to its format code. `None` when the
/// intersection is empty (→ `incompatible_hash_format`).
pub fn negotiate_active_format(
    initiator_order: &[String],
    responder_set: &[String],
) -> Option<u8> {
    initiator_order
        .iter()
        .find(|f| responder_set.iter().any(|r| r == *f))
        .and_then(|f| entity_hash::format_code_for_string(f))
}

/// Connection handshake state.
pub struct Connection {
    pub state: ConnectionState,
    pub local_peer_id: PeerId,
    pub remote_peer_id: Option<PeerId>,
    pub remote_public_key: Option<Vec<u8>>,
    pub local_nonce: Vec<u8>,
    pub remote_nonce: Option<Vec<u8>>,
    /// The remote's **authored** identity `content_hash` — the `signer`
    /// field of the verified authenticate signature (§4.6). This is the
    /// canonical grantee reference per V7 §1.8: the responder MUST use this
    /// authored hash and MUST NOT re-derive the remote identity under its
    /// own format. Set in `process_authenticate`.
    pub remote_identity_hash: Option<Hash>,
    /// This peer's advertised `hash_formats` (preference-ordered, §4.5).
    pub local_hash_formats: Vec<String>,
    /// This peer's advertised `key_types` accept-set (§4.5).
    pub local_key_types: Vec<String>,
    /// This peer's own identity `key_type` label (mutual-verifiability, §4.5).
    pub local_key_type: String,
    /// The negotiated active `content_hash_format` for this connection
    /// (§4.5a). Defaults to the peer's home format until hello negotiation
    /// resolves it; both responder (`process_hello`) and initiator
    /// (`negotiate_active_from_response`) converge on the same value.
    pub active_hash_format: u8,
}

impl Connection {
    pub fn new(local_peer_id: PeerId) -> Self {
        let mut nonce = vec![0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        Self {
            state: ConnectionState::AwaitingHello,
            local_peer_id,
            remote_peer_id: None,
            remote_public_key: None,
            local_nonce: nonce,
            remote_nonce: None,
            remote_identity_hash: None,
            local_hash_formats: default_advertised_hash_formats(
                entity_hash::HASH_ALGORITHM_SHA256,
            ),
            local_key_types: default_advertised_key_types(),
            local_key_type: KeyType::Ed25519.label().to_string(),
            active_hash_format: entity_hash::HASH_ALGORITHM_SHA256,
        }
    }

    /// Configure this connection's advertised negotiation surface from the
    /// peer's home authoring format and own identity `key_type` (§4.5).
    /// Sets `active_hash_format` to `home_format` as the pre-negotiation
    /// default — overwritten once hello negotiation resolves the active
    /// value. Call immediately after [`Connection::new`].
    pub fn set_local_advertisement(&mut self, home_format: u8, own_key_type: &str) {
        self.local_hash_formats = default_advertised_hash_formats(home_format);
        self.local_key_types = default_advertised_key_types();
        self.local_key_type = own_key_type.to_string();
        self.active_hash_format = home_format;
    }

    /// Initiator-side §4.5 negotiation: derive the active format from the
    /// responder's hello-response advertised set, using *this* (initiator's)
    /// preference order. Converges on the same value the responder computed
    /// in `process_hello`. Empty intersection → `IncompatibleHashFormat`.
    pub fn negotiate_active_from_response(
        &mut self,
        response: &HelloData,
    ) -> Result<u8, ProtocolError> {
        let active = negotiate_active_format(&self.local_hash_formats, &response.hash_formats)
            .ok_or(ProtocolError::IncompatibleHashFormat)?;
        self.active_hash_format = active;
        Ok(active)
    }

    /// Check if the connection is fully established.
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Established
    }

    /// Check if a URI targets the connection path (pre-authorized).
    pub fn is_connect_path(uri: &str) -> bool {
        let path = entity_entity::EntityUri::normalize_path(uri);
        path == CONNECT_PATH || path.starts_with(&format!("{}/", CONNECT_PATH))
    }

    /// Process a hello EXECUTE from the remote peer (§4.1).
    ///
    /// The envelope root must be an EXECUTE entity targeting system/protocol/connect
    /// with operation "hello". The hello data is in the params entity.
    ///
    /// Returns (our_hello_response, request_id).
    pub fn process_hello(
        &mut self,
        envelope: &Envelope,
    ) -> Result<(HelloData, String), ProtocolError> {
        if self.state != ConnectionState::AwaitingHello {
            return Err(ProtocolError::ConnectionError(
                "unexpected hello: not in AwaitingHello state".into(),
            ));
        }

        // Unwrap the EXECUTE envelope
        let exec = parse_connect_execute(&envelope.root)?;

        if exec.uri != CONNECT_PATH {
            return Err(ProtocolError::Invalid(format!(
                "expected URI {}, got {}",
                CONNECT_PATH, exec.uri
            )));
        }
        if exec.operation != "hello" {
            return Err(ProtocolError::Invalid(format!(
                "expected operation hello, got {}",
                exec.operation
            )));
        }

        // Parse hello data from the params entity
        let hello = HelloData::from_entity(&exec.params)?;

        // Validate the remote peer's PeerID format. v7.66 §4.4 surface 6:
        // route `UnsupportedKeyType` to the dedicated `ProtocolError`
        // variant so the wire response carries the
        // `400 unsupported_key_type` registry entry rather than the
        // generic `handshake_failed` code (which is what
        // AGILITY-UNKNOWN-1 fails on at the cross-impl boundary).
        let remote_pid = PeerId::from(hello.peer_id.as_str());
        remote_pid.validate().map_err(|e| match e {
            entity_crypto::CryptoError::UnsupportedKeyType(b) => {
                ProtocolError::UnsupportedKeyType(b)
            }
            other => {
                ProtocolError::ConnectionError(format!("invalid remote peer_id: {}", other))
            }
        })?;

        // §4.5 hash_formats negotiation (single active value). The active
        // `content_hash_format` is the first entry in the **initiator's**
        // (remote's) order that we also support. Empty intersection →
        // `400 incompatible_hash_format` (§4.7).
        let active = negotiate_active_format(&hello.hash_formats, &self.local_hash_formats)
            .ok_or(ProtocolError::IncompatibleHashFormat)?;
        self.active_hash_format = active;

        // §4.5 key_types accept-set, mutual verifiability: our own
        // identity `key_type` MUST appear in the initiator's advertised
        // set, else we cannot be verified by them → `400 unsupported_key_type`
        // (the canonical earliest reject point per §4.5). The symmetric
        // direction (our advertised set covering the initiator's key_type)
        // is enforced at authenticate / peer_id decode as defense-in-depth.
        if !hello.key_types.iter().any(|k| k == &self.local_key_type) {
            let own_byte = KeyType::from_label(&self.local_key_type)
                .map(|k| k.byte())
                .unwrap_or(0xFE);
            return Err(ProtocolError::UnsupportedKeyType(own_byte));
        }

        self.remote_peer_id = Some(remote_pid);
        self.remote_nonce = Some(hello.nonce.clone());
        self.state = ConnectionState::AwaitingAuthenticate;

        // Build our hello response, advertising our negotiation surface.
        Ok((
            HelloData {
                peer_id: self.local_peer_id.as_str().to_string(),
                nonce: self.local_nonce.clone(),
                protocols: vec!["entity-core/1.0".to_string()],
                hash_formats: self.local_hash_formats.clone(),
                key_types: self.local_key_types.clone(),
                timestamp: None,
            },
            exec.request_id,
        ))
    }

    /// Process an authenticate EXECUTE from the remote peer (§4.1).
    ///
    /// The envelope root must be an EXECUTE entity targeting system/protocol/connect
    /// with operation "authenticate". The authenticate data is in the params entity.
    /// The signature targets the params entity's content_hash (not the EXECUTE).
    ///
    /// Returns (remote_peer_id, request_id).
    pub fn process_authenticate(
        &mut self,
        envelope: &Envelope,
    ) -> Result<(PeerId, String), ProtocolError> {
        if self.state != ConnectionState::AwaitingAuthenticate {
            return Err(ProtocolError::ConnectionError(
                "unexpected authenticate: not in AwaitingAuthenticate state".into(),
            ));
        }

        // Unwrap the EXECUTE envelope
        let exec = parse_connect_execute(&envelope.root)?;

        if exec.uri != CONNECT_PATH {
            return Err(ProtocolError::Invalid(format!(
                "expected URI {}, got {}",
                CONNECT_PATH, exec.uri
            )));
        }
        if exec.operation != "authenticate" {
            return Err(ProtocolError::Invalid(format!(
                "expected operation authenticate, got {}",
                exec.operation
            )));
        }

        // Parse authenticate data from the params entity
        let auth_data = AuthenticateData::from_entity(&exec.params)?;

        // Verify the nonce matches what we sent
        if auth_data.nonce != self.local_nonce {
            return Err(ProtocolError::ConnectionError(
                "authenticate nonce does not match".into(),
            ));
        }

        // Verify signature on the authenticate entity (params entity, not EXECUTE root).
        // The authenticate entity may be in the envelope's included map, or we can
        // look for a signature targeting its content_hash.
        let params_hash = exec.params.content_hash;
        let sig_entity = envelope
            .find_signature_for(&params_hash)
            .ok_or(ProtocolError::MissingSignature)?;
        let sig_data = SignatureData::from_entity(sig_entity)
            .map_err(|e| ProtocolError::Invalid(e.to_string()))?;

        // v7.67 Phase 2 (MATRIX-M2): dispatch signature verification on the
        // remote's key_type, decoded from its presented peer_id wire-prefix,
        // rather than assuming Ed25519. `public_key` length is validated by
        // `verify_for_key_type` against the decoded scheme.
        let pub_key = auth_data.public_key.as_slice();
        let claimed_pid = PeerId::from(auth_data.peer_id.as_str());
        let remote_key_type = KeyType::from_byte(
            claimed_pid
                .decode()
                .map_err(|e| ProtocolError::Invalid(format!("authenticate peer_id decode: {e}")))?
                .key_type,
        )
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;

        verify_for_key_type(
            remote_key_type,
            pub_key,
            &params_hash.to_bytes(),
            &sig_data.signature,
        )
        .map_err(|_| ProtocolError::InvalidSignature)?;

        // Verify the PeerId matches the public key. Per v7.64 §1.5,
        // PeerIDs come in two forms (identity-multihash and SHA-256
        // fingerprint); `verify_public_key_bytes` handles both forms and
        // variable-length keys (32-byte Ed25519 / 57-byte Ed448) — re-
        // deriving a single form locally and string-comparing would reject
        // the other form for the same keypair.
        if !claimed_pid.verify_public_key_bytes(pub_key) {
            return Err(ProtocolError::ConnectionError(
                "authenticate peer_id does not match public key".into(),
            ));
        }

        self.state = ConnectionState::Established;
        let remote_pid = PeerId::from(auth_data.peer_id.as_str());
        self.remote_peer_id = Some(remote_pid.clone());
        self.remote_public_key = Some(pub_key.to_vec());
        // V7 §1.8 / §4.6: the canonical reference to the remote's identity
        // is the authored `content_hash` it presented as `signature.signer`
        // (just used to verify the authenticate signature). Capture it so
        // the connect handler uses it directly as the cap `grantee` rather
        // than re-deriving the identity entity under the local format.
        self.remote_identity_hash = Some(sig_data.signer);

        Ok((remote_pid, exec.request_id))
    }
}

// ---------------------------------------------------------------------------
// EXECUTE helpers for connect operations
// ---------------------------------------------------------------------------

/// Parsed EXECUTE data for connect operations.
struct ConnectExecute {
    request_id: String,
    uri: String,
    operation: String,
    params: Entity,
}

/// Parse an EXECUTE entity's data for a connect operation.
///
/// Validates the entity type is system/protocol/execute, then extracts
/// request_id, uri, operation, and params (decoded as an Entity).
fn parse_connect_execute(execute: &Entity) -> Result<ConnectExecute, ProtocolError> {
    if execute.entity_type != TYPE_EXECUTE {
        return Err(ProtocolError::Invalid(format!(
            "expected {}, got {}",
            TYPE_EXECUTE, execute.entity_type
        )));
    }

    let value: ciborium::Value = ciborium::from_reader(execute.data.as_slice())
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| ProtocolError::Invalid("execute data must be a map".into()))?;

    let mut request_id = None;
    let mut uri = None;
    let mut operation = None;
    let mut params_value = None;

    for (k, v) in map {
        match k.as_text() {
            Some("request_id") => request_id = v.as_text().map(|s| s.to_string()),
            Some("uri") => uri = v.as_text().map(|s| s.to_string()),
            Some("operation") => operation = v.as_text().map(|s| s.to_string()),
            Some("params") => params_value = Some(v),
            _ => {}
        }
    }

    let request_id = request_id.ok_or(ProtocolError::MissingField("request_id"))?;
    let uri = uri.ok_or(ProtocolError::MissingField("uri"))?;
    let operation = operation.ok_or(ProtocolError::MissingField("operation"))?;
    let params_v = params_value.ok_or(ProtocolError::MissingField("params"))?;
    let params = decode_entity_from_value(params_v)?;

    Ok(ConnectExecute {
        request_id,
        uri,
        operation,
        params,
    })
}

/// Decode an Entity from a ciborium::Value (a CBOR map with type, data, content_hash).
pub(crate) fn decode_entity_from_value(value: &ciborium::Value) -> Result<Entity, ProtocolError> {
    let map = value
        .as_map()
        .ok_or_else(|| ProtocolError::Invalid("params must be a CBOR map (entity)".into()))?;

    let mut entity_type = None;
    let mut entity_data = None;
    let mut content_hash = None;

    for (k, v) in map {
        match k.as_text() {
            Some("type") => entity_type = v.as_text().map(|s| s.to_string()),
            Some("data") => {
                let mut buf = Vec::new();
                ciborium::into_writer(v, &mut buf)
                    .map_err(|e| ProtocolError::Invalid(e.to_string()))?;
                entity_data = Some(buf);
            }
            Some("content_hash") => {
                if let Some(bytes) = v.as_bytes() {
                    content_hash = Some(
                        Hash::from_bytes(bytes)
                            .map_err(|e| ProtocolError::Invalid(e.to_string()))?,
                    );
                }
            }
            _ => {}
        }
    }

    let entity_type = entity_type.ok_or(ProtocolError::MissingField("type"))?;
    let data = entity_data.ok_or(ProtocolError::MissingField("data"))?;
    let content_hash = content_hash.ok_or(ProtocolError::MissingField("content_hash"))?;

    Ok(Entity {
        entity_type,
        data,
        content_hash,
    })
}

/// Build an EXECUTE entity for a connect operation (§4.1).
///
/// The params entity is embedded as a nested CBOR map in the EXECUTE data.
pub fn build_connect_execute(
    request_id: &str,
    operation: &str,
    params_entity: &Entity,
) -> Result<Entity, ProtocolError> {
    let params_encoded = entity_wire::encode_entity(params_entity);

    // Build EXECUTE data as manually-constructed CBOR.
    // ECF key ordering (by encoded key byte length, then lexicographic):
    //   "uri"        (3 chars) -> 4 encoded bytes
    //   "params"     (6 chars) -> 7 encoded bytes
    //   "operation"  (9 chars) -> 10 encoded bytes
    //   "request_id" (10 chars) -> 11 encoded bytes
    let mut data = Vec::new();
    data.push(0xA4); // map(4)

    // "uri"
    entity_ecf::encode_cbor_text(&mut data, "uri");
    entity_ecf::encode_cbor_text(&mut data, CONNECT_PATH);

    // "params"
    entity_ecf::encode_cbor_text(&mut data, "params");
    data.extend_from_slice(&params_encoded);

    // "operation"
    entity_ecf::encode_cbor_text(&mut data, "operation");
    entity_ecf::encode_cbor_text(&mut data, operation);

    // "request_id"
    entity_ecf::encode_cbor_text(&mut data, "request_id");
    entity_ecf::encode_cbor_text(&mut data, request_id);

    Entity::new(TYPE_EXECUTE, data).map_err(|e| ProtocolError::Invalid(e.to_string()))
}

/// Build an authenticate EXECUTE envelope with signature (§4.6).
///
/// The authenticate entity is wrapped in an EXECUTE targeting system/protocol/connect
/// with operation "authenticate". The signature targets the authenticate entity.
pub fn build_authenticate_envelope(
    keypair: &IdentityKeypair,
    remote_nonce: &[u8],
    active_format: u8,
) -> Result<Envelope, ProtocolError> {
    let peer_id = keypair.peer_id();
    let key_type_label = keypair.key_type().label();

    // Build authenticate entity
    let auth_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("key_type"),
            entity_ecf::text(key_type_label),
        ),
        (
            entity_ecf::text("nonce"),
            entity_ecf::Value::Bytes(remote_nonce.to_vec()),
        ),
        (
            entity_ecf::text("peer_id"),
            entity_ecf::text(peer_id.as_str()),
        ),
        (
            entity_ecf::text("public_key"),
            entity_ecf::Value::Bytes(keypair.public_key_bytes().to_vec()),
        ),
    ]));

    // §4.5a: author every entity transmitted on this connection under the
    // negotiated active `content_hash_format`.
    let auth_entity = Entity::new_with_format(TYPE_AUTHENTICATE, auth_data, active_format)
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;

    // Build identity entity under the active format (§4.5a — the signer
    // reference must be the active-format identity hash, not the peer's
    // home-format startup identity).
    let identity = keypair
        .peer_entity_with_format(active_format)
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;
    let identity_hash = identity.content_hash;

    // Sign the authenticate entity's content hash
    let sig_bytes = keypair.sign(&auth_entity.content_hash.to_bytes());

    // Build signature entity
    let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("algorithm"),
            entity_ecf::text(key_type_label),
        ),
        (
            entity_ecf::text("signature"),
            entity_ecf::Value::Bytes(sig_bytes.to_vec()),
        ),
        (
            entity_ecf::text("signer"),
            entity_ecf::Value::Bytes(identity_hash.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("target"),
            entity_ecf::Value::Bytes(auth_entity.content_hash.to_bytes().to_vec()),
        ),
    ]));
    let sig_entity = Entity::new_with_format(TYPE_SIGNATURE, sig_data, active_format)
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;

    // Wrap authenticate entity in an EXECUTE
    let exec_entity =
        build_connect_execute("connect-authenticate", "authenticate", &auth_entity)?;

    // Envelope: root = EXECUTE, included = [auth_entity, identity, signature]
    let mut envelope = Envelope::new(exec_entity);
    envelope.include(auth_entity);
    envelope.include(identity);
    envelope.include(sig_entity);

    Ok(envelope)
}
