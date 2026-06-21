//! `system/peer/session/{remote_peer_id}` — R6 session+capability tree entity.
//!
//! R6 (transport-family live-reachability and session-lifecycle
//! §7.2, ruled §9) makes §6.1's "Sessions are identified by `peer_id`
//! and persist in the entity tree … held capability tokens" literal:
//! each peer stores one `system/peer/session/{remote_peer_id}` entity
//! per remote it has handshaken with. The entity holds the
//! connection-handshake capabilities and the auth context.
//!
//! **The session entity is the durable per-peer AUTH record** — it
//! answers exactly one question for §10 dispatch: *"do I already hold
//! a valid capability to talk to this peer, or must I re-handshake?"*
//! It is NOT the reachability/liveness/lifecycle record. Those live
//! in `system/peer/transport/*`, `system/connection/{peer}`, and
//! `system/peer/status/{peer}` respectively (§9.0).
//!
//! **§9 schema (the convergence target):**
//! ```text
//! system/peer/session/{remote_peer_id} := {
//!   remote_peer_id,                       // text
//!   remote_identity_hash,                 // 33-byte bstr (system/hash)
//!   remote_public_key?,                   // bytes, optional denorm (R6-g)
//!   held_capability:   { hash, chain },   // cap I wield to dispatch to remote (R6-a)
//!   minted_capability?:{ hash, chain },   // cap I issued to remote — R3a anchor (R6-a)
//!   granted_at,                           // uint ms — = last handshake
//!   expires_at?,                          // uint ms, omitempty — validity window
//! }
//! ```
//!
//! **Bidirectional resolution (§9.1 R6-a):** one entity per peer, two
//! cap fields. `held_capability` is the cap remote granted me (dialer
//! writes this); `minted_capability` is the cap I issued remote (granter
//! writes this — R3a idempotency anchor). In a bidirectional pair,
//! A's `minted_capability` for B *is the same cap entity* as B's
//! `held_capability` from A — one cap, recorded from both ends.
//! Back-direction *delivery* auth remains `deliver_token` (§7.1 #2);
//! `minted_capability` is granter bookkeeping, NOT a back-delivery cap.
//!
//! **Dropped vs §7.2 strawman:** `last_active` (R6-b — liveness, not
//! auth; `system/peer/status.last_seen` owns it) + `status` (R6-c —
//! lifecycle is `system/peer/status`'s job; validity is derivable
//! from `expires_at`).

use entity_entity::Entity;
use entity_hash::Hash;

/// Entity-type string for the R6 session entity (§9.3).
pub const TYPE_PEER_SESSION: &str = "system/peer/session";

/// Capability reference: the leaf hash + denormalized delegation chain
/// from leaf → root (length ≥ 1; R6-d). For handshake-minted root caps
/// (`parent: None`) chain is `[leaf_hash]`. For delegated caps the
/// chain walks back to root, length ≥ 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRef {
    pub hash: Hash,
    pub chain: Vec<Hash>,
}

/// Decoded `system/peer/session/{remote_peer_id}` entity (§9.3).
///
/// Both `held_capability` and `minted_capability` are `Option<>` —
/// each peer populates the field corresponding to the direction it
/// participated in. A peer that has dialed remote but not been dialed
/// by remote has `held` set, `minted` absent (and vice versa). Both
/// set when the relationship is bidirectional.
///
/// Hash fields use the 33-byte bstr wire shape per
/// `[[feedback_system_hash_wire_shape]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSession {
    /// Base58 string of the remote peer's `peer_id`. The path segment
    /// `{remote_peer_id}` matches this verbatim.
    pub remote_peer_id: String,

    /// Content hash of the remote's `system/peer` identity entity.
    pub remote_identity_hash: Hash,

    /// Ed25519 public key of the remote (32 bytes). R6-g: OPTIONAL
    /// denormalization for inspectability without an extra
    /// content-store fetch. Peers MAY omit and deref
    /// `remote_identity_hash` → identity entity → `public_key`.
    pub remote_public_key: Option<Vec<u8>>,

    /// Cap I wield to dispatch outbound to remote (the cap remote
    /// granted me at handshake). Dialer-side writes this. §10
    /// dispatch reads this to answer "do I skip the handshake?"
    /// (§9.0).
    pub held_capability: Option<CapabilityRef>,

    /// Cap I issued to remote at handshake (granter-side bookkeeping;
    /// the R3a idempotency anchor). NOT a reverse-delivery cap —
    /// back-direction delivery uses `deliver_token` (§9.1 R6-a
    /// reconciliation with §7.1 #2).
    pub minted_capability: Option<CapabilityRef>,

    /// Wall-clock ms epoch — last handshake (matches the freshly-
    /// minted cap's `created_at` on the writing side).
    pub granted_at: u64,

    /// Wall-clock ms epoch when the (relevant) cap expires; `None`
    /// when caps have no expiry. Emitted `omitempty`.
    pub expires_at: Option<u64>,
}

/// Errors decoding a session entity.
#[derive(Debug, thiserror::Error)]
pub enum SessionEntityDecodeError {
    /// Entity type didn't match `system/peer/session`.
    #[error("expected entity_type {TYPE_PEER_SESSION}, got {0}")]
    UnexpectedType(String),
    /// CBOR decode failed.
    #[error("cbor decode: {0}")]
    Cbor(String),
    /// Data root wasn't a CBOR map.
    #[error("session data is not a CBOR map")]
    NotAMap,
    /// A required field was missing.
    #[error("session missing required field: {0}")]
    MissingField(&'static str),
    /// A required field had the wrong CBOR shape.
    #[error("session field {field} has wrong shape: {detail}")]
    BadFieldShape {
        /// The field name.
        field: &'static str,
        /// Diagnostic detail.
        detail: String,
    },
}

impl PeerSession {
    /// Tree path under the local peer's root where this session lives.
    /// Caller prefixes with `/{local_peer_id}/`.
    ///
    /// Format: `system/peer/session/{peer_id_hex}` per V7 §1.4 v7.64
    /// positional encoding rule. The `peer_id_hex` is the lowercase hex
    /// of the remote peer's `system/peer` entity content_hash (33 bytes,
    /// 66 hex chars). See [`entity_crypto::peer_identity_hash`] for the
    /// computation; instances normally already carry this on
    /// `remote_identity_hash` — use [`PeerSession::path_for`].
    pub fn relative_path(remote_identity_hash: &Hash) -> String {
        format!("system/peer/session/{}", remote_identity_hash.to_hex())
    }

    /// Convenience: `system/peer/session/{peer_id_hex}` for this session.
    pub fn path_for(&self) -> String {
        Self::relative_path(&self.remote_identity_hash)
    }

    /// Construct a session entity for the granter side: I just minted
    /// a cap for the remote. `held_capability` is left absent unless
    /// this is a merge over an existing dialer-side entry.
    pub fn new_minted(
        remote_peer_id: impl Into<String>,
        remote_identity_hash: Hash,
        remote_public_key: Option<Vec<u8>>,
        minted: CapabilityRef,
        granted_at: u64,
        expires_at: Option<u64>,
    ) -> Self {
        Self {
            remote_peer_id: remote_peer_id.into(),
            remote_identity_hash,
            remote_public_key,
            held_capability: None,
            minted_capability: Some(minted),
            granted_at,
            expires_at,
        }
    }

    /// Construct a session entity for the dialer side: I just received
    /// a cap from remote and now wield it. `minted_capability` is left
    /// absent unless this is a merge over an existing granter-side entry.
    pub fn new_held(
        remote_peer_id: impl Into<String>,
        remote_identity_hash: Hash,
        remote_public_key: Option<Vec<u8>>,
        held: CapabilityRef,
        granted_at: u64,
        expires_at: Option<u64>,
    ) -> Self {
        Self {
            remote_peer_id: remote_peer_id.into(),
            remote_identity_hash,
            remote_public_key,
            held_capability: Some(held),
            minted_capability: None,
            granted_at,
            expires_at,
        }
    }

    /// Merge a freshly-written `held_capability` into an existing
    /// session entity (preserving `minted_capability` + identity).
    /// Used by the dialer when a granter-side entity already exists.
    pub fn with_held(mut self, held: CapabilityRef, granted_at: u64) -> Self {
        self.held_capability = Some(held);
        self.granted_at = granted_at;
        self
    }

    /// Merge a freshly-written `minted_capability` into an existing
    /// session entity (preserving `held_capability` + identity).
    /// Used by the granter when a dialer-side entity already exists.
    pub fn with_minted(mut self, minted: CapabilityRef, granted_at: u64) -> Self {
        self.minted_capability = Some(minted);
        self.granted_at = granted_at;
        self
    }

    /// Encode to a `system/peer/session` `Entity`. CBOR-map data with
    /// keys in alphabetic order (ECF determinism). Hash fields use
    /// the 33-byte bstr wire shape. `held_capability`,
    /// `minted_capability`, `remote_public_key`, and `expires_at` are
    /// omitted entirely when `None` (true CBOR absence).
    pub fn to_entity(&self) -> Entity {
        let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();

        // Insert in alphabetic order.
        if let Some(exp) = self.expires_at {
            fields.push((
                entity_ecf::text("expires_at"),
                entity_ecf::Value::Integer(exp.into()),
            ));
        }
        fields.push((
            entity_ecf::text("granted_at"),
            entity_ecf::Value::Integer(self.granted_at.into()),
        ));
        if let Some(ref held) = self.held_capability {
            fields.push((
                entity_ecf::text("held_capability"),
                encode_capability_ref(held),
            ));
        }
        if let Some(ref minted) = self.minted_capability {
            fields.push((
                entity_ecf::text("minted_capability"),
                encode_capability_ref(minted),
            ));
        }
        fields.push((
            entity_ecf::text("remote_identity_hash"),
            entity_ecf::Value::Bytes(self.remote_identity_hash.to_bytes().to_vec()),
        ));
        fields.push((
            entity_ecf::text("remote_peer_id"),
            entity_ecf::text(&self.remote_peer_id),
        ));
        if let Some(ref pk) = self.remote_public_key {
            fields.push((
                entity_ecf::text("remote_public_key"),
                entity_ecf::Value::Bytes(pk.clone()),
            ));
        }

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        Entity::new(TYPE_PEER_SESSION, data)
            .expect("entity construction for system/peer/session")
    }

    /// Decode a `system/peer/session` `Entity`.
    pub fn from_entity(entity: &Entity) -> Result<Self, SessionEntityDecodeError> {
        if entity.entity_type != TYPE_PEER_SESSION {
            return Err(SessionEntityDecodeError::UnexpectedType(
                entity.entity_type.clone(),
            ));
        }
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| SessionEntityDecodeError::Cbor(e.to_string()))?;
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(SessionEntityDecodeError::NotAMap),
        };

        let remote_peer_id = field_text(&map, "remote_peer_id")
            .ok_or(SessionEntityDecodeError::MissingField("remote_peer_id"))?;
        let remote_identity_hash = field_hash(&map, "remote_identity_hash")?
            .ok_or(SessionEntityDecodeError::MissingField("remote_identity_hash"))?;
        let remote_public_key = field_bytes(&map, "remote_public_key");
        let granted_at = field_uint(&map, "granted_at")
            .ok_or(SessionEntityDecodeError::MissingField("granted_at"))?;
        let expires_at = field_uint(&map, "expires_at");

        let held_capability = decode_capability_ref(&map, "held_capability")?;
        let minted_capability = decode_capability_ref(&map, "minted_capability")?;

        Ok(Self {
            remote_peer_id,
            remote_identity_hash,
            remote_public_key,
            held_capability,
            minted_capability,
            granted_at,
            expires_at,
        })
    }
}

fn encode_capability_ref(c: &CapabilityRef) -> entity_ecf::Value {
    let chain_arr = entity_ecf::Value::Array(
        c.chain
            .iter()
            .map(|h| entity_ecf::Value::Bytes(h.to_bytes().to_vec()))
            .collect(),
    );
    // Alphabetic: chain, hash.
    entity_ecf::Value::Map(vec![
        (entity_ecf::text("chain"), chain_arr),
        (
            entity_ecf::text("hash"),
            entity_ecf::Value::Bytes(c.hash.to_bytes().to_vec()),
        ),
    ])
}

fn decode_capability_ref(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &'static str,
) -> Result<Option<CapabilityRef>, SessionEntityDecodeError> {
    let cap_map = match field_lookup(map, key) {
        Some(ciborium::Value::Map(m)) => m,
        Some(_) => {
            return Err(SessionEntityDecodeError::BadFieldShape {
                field: key,
                detail: "expected CBOR map".into(),
            })
        }
        None => return Ok(None),
    };
    let hash = field_hash(cap_map, "hash")?.ok_or(SessionEntityDecodeError::BadFieldShape {
        field: key,
        detail: "missing nested `hash`".into(),
    })?;
    let chain = match field_lookup(cap_map, "chain") {
        Some(ciborium::Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                let bytes = match v {
                    ciborium::Value::Bytes(b) => b,
                    _ => {
                        return Err(SessionEntityDecodeError::BadFieldShape {
                            field: key,
                            detail: format!("chain element {} is not bytes", i),
                        })
                    }
                };
                out.push(Hash::from_bytes(bytes).map_err(|e| {
                    SessionEntityDecodeError::BadFieldShape {
                        field: key,
                        detail: format!("chain element {}: {}", i, e),
                    }
                })?);
            }
            out
        }
        Some(_) => {
            return Err(SessionEntityDecodeError::BadFieldShape {
                field: key,
                detail: "chain is not a CBOR array".into(),
            })
        }
        None => {
            return Err(SessionEntityDecodeError::BadFieldShape {
                field: key,
                detail: "missing nested `chain`".into(),
            })
        }
    };
    if chain.is_empty() {
        return Err(SessionEntityDecodeError::BadFieldShape {
            field: key,
            detail: "chain MUST have length ≥ 1 (§9.1 R6-d)".into(),
        });
    }
    Ok(Some(CapabilityRef { hash, chain }))
}

// --- field helpers ---

fn field_lookup<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter().find_map(|(k, v)| match k {
        ciborium::Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn field_text(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<String> {
    field_lookup(map, key).and_then(|v| match v {
        ciborium::Value::Text(s) => Some(s.clone()),
        _ => None,
    })
}

fn field_bytes(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<Vec<u8>> {
    field_lookup(map, key).and_then(|v| match v {
        ciborium::Value::Bytes(b) => Some(b.clone()),
        _ => None,
    })
}

fn field_uint(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<u64> {
    field_lookup(map, key).and_then(|v| match v {
        ciborium::Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    })
}

fn field_hash(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &'static str,
) -> Result<Option<Hash>, SessionEntityDecodeError> {
    match field_lookup(map, key) {
        Some(ciborium::Value::Bytes(b)) => Hash::from_bytes(b)
            .map(Some)
            .map_err(|e| SessionEntityDecodeError::BadFieldShape {
                field: key,
                detail: e.to_string(),
            }),
        Some(_) => Err(SessionEntityDecodeError::BadFieldShape {
            field: key,
            detail: "expected 33-byte CBOR bstr".into(),
        }),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_hash(seed: u8) -> Hash {
        let mut digest = [0u8; 32];
        digest[0] = seed;
        Hash::new(0x00, digest)
    }

    fn fixture_cap_ref(seed: u8) -> CapabilityRef {
        CapabilityRef {
            hash: fixture_hash(seed),
            chain: vec![fixture_hash(seed)],
        }
    }

    fn fixture_minted_only() -> PeerSession {
        PeerSession::new_minted(
            "2KN3pAqMPYeVDnYXG7qk9geYmqTpmmcwyGL7EK5o8yuwLt",
            fixture_hash(0xa1),
            Some(vec![1u8; 32]),
            fixture_cap_ref(0xc1),
            1_700_000_000_000,
            None,
        )
    }

    fn fixture_held_only() -> PeerSession {
        PeerSession::new_held(
            "2KN3pAqMPYeVDnYXG7qk9geYmqTpmmcwyGL7EK5o8yuwLt",
            fixture_hash(0xa1),
            Some(vec![1u8; 32]),
            fixture_cap_ref(0xc2),
            1_700_000_000_000,
            None,
        )
    }

    #[test]
    fn r6_session_relative_path_uses_remote_identity_hex() {
        // v7.64: path-segment is hex of remote's `system/peer` content_hash.
        let h = fixture_hash(0xab);
        let hex = h.to_hex();
        assert_eq!(
            PeerSession::relative_path(&h),
            format!("system/peer/session/{}", hex)
        );
        // 66 hex chars (algorithm byte 0x00 + 32-byte SHA-256 digest).
        assert_eq!(hex.len(), 66);
        assert!(hex.starts_with("00"));
    }

    #[test]
    fn r6_session_entity_type_string() {
        let entity = fixture_minted_only().to_entity();
        assert_eq!(entity.entity_type, "system/peer/session");
    }

    #[test]
    fn r6_session_minted_only_round_trips() {
        let original = fixture_minted_only();
        let entity = original.to_entity();
        let decoded = PeerSession::from_entity(&entity).unwrap();
        assert_eq!(decoded, original);
        assert!(decoded.held_capability.is_none());
        assert!(decoded.minted_capability.is_some());
    }

    #[test]
    fn r6_session_held_only_round_trips() {
        let original = fixture_held_only();
        let entity = original.to_entity();
        let decoded = PeerSession::from_entity(&entity).unwrap();
        assert_eq!(decoded, original);
        assert!(decoded.held_capability.is_some());
        assert!(decoded.minted_capability.is_none());
    }

    #[test]
    fn r6_session_bidirectional_round_trips() {
        let original = fixture_minted_only().with_held(
            fixture_cap_ref(0xc3),
            1_700_000_010_000,
        );
        assert!(original.held_capability.is_some());
        assert!(original.minted_capability.is_some());
        let entity = original.to_entity();
        let decoded = PeerSession::from_entity(&entity).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn r6_session_round_trips_with_expires_at() {
        let mut original = fixture_minted_only();
        original.expires_at = Some(1_700_000_900_000);
        let entity = original.to_entity();
        let decoded = PeerSession::from_entity(&entity).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn r6_session_round_trips_with_delegation_chain() {
        let mut original = fixture_minted_only();
        original.minted_capability = Some(CapabilityRef {
            hash: fixture_hash(0xc1),
            chain: vec![fixture_hash(0xc1), fixture_hash(0xc0)],
        });
        let entity = original.to_entity();
        let decoded = PeerSession::from_entity(&entity).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.minted_capability.unwrap().chain.len(), 2);
    }

    #[test]
    fn r6_session_round_trips_without_remote_public_key() {
        let mut original = fixture_minted_only();
        original.remote_public_key = None;
        let entity = original.to_entity();
        let decoded = PeerSession::from_entity(&entity).unwrap();
        assert_eq!(decoded, original);
        assert!(decoded.remote_public_key.is_none());
    }

    #[test]
    fn r6_session_omits_optionals_when_none() {
        let mut original = fixture_minted_only();
        original.expires_at = None;
        original.remote_public_key = None;
        original.held_capability = None;
        let entity = original.to_entity();
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        for absent in ["expires_at", "remote_public_key", "held_capability"] {
            let present = map
                .iter()
                .any(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == absent));
            assert!(!present, "{} must be absent when None", absent);
        }
    }

    #[test]
    fn r6_session_hash_fields_are_33_byte_bstr() {
        // [[feedback_system_hash_wire_shape]]: 33-byte bstr no matter
        // where they appear (top-level field, nested map field, array
        // element).
        let mut original = fixture_minted_only();
        original.held_capability = Some(fixture_cap_ref(0xc3));
        let entity = original.to_entity();
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => panic!("expected map"),
        };

        // Top-level remote_identity_hash.
        let rih = map
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Text(s) if s == "remote_identity_hash" => Some(v),
                _ => None,
            })
            .unwrap();
        match rih {
            ciborium::Value::Bytes(b) => assert_eq!(b.len(), 33),
            _ => panic!("remote_identity_hash must be CBOR bytes"),
        }

        // Both capability nested maps.
        for cap_key in ["held_capability", "minted_capability"] {
            let cap_map = map
                .iter()
                .find_map(|(k, v)| match k {
                    ciborium::Value::Text(s) if s == cap_key => Some(v),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{} should be present", cap_key));
            let cap_map = match cap_map {
                ciborium::Value::Map(m) => m,
                _ => panic!("{} must be a CBOR map", cap_key),
            };
            let cap_hash = cap_map
                .iter()
                .find_map(|(k, v)| match k {
                    ciborium::Value::Text(s) if s == "hash" => Some(v),
                    _ => None,
                })
                .unwrap();
            match cap_hash {
                ciborium::Value::Bytes(b) => assert_eq!(b.len(), 33),
                _ => panic!("{}.hash must be CBOR bytes", cap_key),
            }
            let chain = cap_map
                .iter()
                .find_map(|(k, v)| match k {
                    ciborium::Value::Text(s) if s == "chain" => Some(v),
                    _ => None,
                })
                .unwrap();
            match chain {
                ciborium::Value::Array(arr) => {
                    for elt in arr {
                        match elt {
                            ciborium::Value::Bytes(b) => assert_eq!(b.len(), 33),
                            _ => panic!("{}.chain element must be CBOR bytes", cap_key),
                        }
                    }
                }
                _ => panic!("{}.chain must be CBOR array", cap_key),
            }
        }
    }

    #[test]
    fn r6_session_decode_rejects_wrong_type() {
        let other = Entity::new("some/other/type", b"\xa0".to_vec()).unwrap();
        let err = PeerSession::from_entity(&other).unwrap_err();
        assert!(matches!(err, SessionEntityDecodeError::UnexpectedType(_)));
    }

    #[test]
    fn r6_session_decode_rejects_chain_empty() {
        // Hand-build a session with a zero-length chain — R6-d says
        // length ≥ 1.
        let bad_cap = entity_ecf::Value::Map(vec![
            (entity_ecf::text("chain"), entity_ecf::Value::Array(vec![])),
            (
                entity_ecf::text("hash"),
                entity_ecf::Value::Bytes(fixture_hash(0xc1).to_bytes().to_vec()),
            ),
        ]);
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("granted_at"),
                entity_ecf::Value::Integer(1u64.into()),
            ),
            (entity_ecf::text("minted_capability"), bad_cap),
            (
                entity_ecf::text("remote_identity_hash"),
                entity_ecf::Value::Bytes(fixture_hash(0x01).to_bytes().to_vec()),
            ),
            (entity_ecf::text("remote_peer_id"), entity_ecf::text("p")),
        ]));
        let entity = Entity::new(TYPE_PEER_SESSION, data).unwrap();
        let err = PeerSession::from_entity(&entity).unwrap_err();
        assert!(matches!(
            err,
            SessionEntityDecodeError::BadFieldShape { field: "minted_capability", .. }
        ));
    }
}
