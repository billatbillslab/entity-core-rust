//! Bidirectional conversions between this crate's wire types and the real
//! SDK / kernel types.
//!
//! Enabled by `feature = "conversions"`. `wasm-worker-proxy` and
//! `wasm-worker-host` both enable it; consumers wanting only the wire types
//! (e.g., for raw serialization or routing) leave it off and keep their
//! dependency graph small.
//!
//! # Direction conventions
//!
//! - **Wire → SDK** is `TryFrom` because parsing can fail (e.g., a
//!   `WireHash` payload may not be 33 bytes; an unknown `WireErrorKind`
//!   could appear during version mismatch). Failures map to
//!   [`ConversionError`].
//! - **SDK → Wire** is `From` and infallible — given a valid SDK value,
//!   construction is mechanical field-copy.
//!
//! # Round-trip property
//!
//! For every conversion pair `(SDK, Wire)`, `SDK -> Wire -> SDK` is the
//! identity. The reverse direction is identity up to `WireError`'s human
//! `message` field (which is descriptive, not load-bearing) and any wire
//! types that intentionally don't model the full SDK shape (notably
//! [`WireExecuteOptions`] — see its doc).
//!
//! Phase 1 spike: only the conversions actually called from the proxy/host
//! Phase 1 paths are implemented here. Phase 1's later steps (full host
//! dispatch, cache materialization) may add more.

use crate::{
    CasFailure, CasFailureKind, WireEntity, WireError, WireErrorKind, WireExecuteOptions,
    WireFieldInfo, WireHandlerInfo, WireHandlerResult, WireHash, WireListingEntry,
    WirePeerMetadata, WireQueryMatch, WireQueryResults, WireTypeInfo,
};
use entity_capability::ResourceTarget;
use entity_entity::Entity;
use entity_handler::{ExecuteOptions, HandlerResult};
use entity_hash::{Hash, HashError};
use entity_store::LocationEntry;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConversionError {
    #[error("hash parse: {0}")]
    Hash(#[from] HashError),
    #[error("entity construct: {0}")]
    Entity(String),
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

impl From<Hash> for WireHash {
    fn from(h: Hash) -> Self {
        WireHash(h.to_bytes().to_vec())
    }
}

impl TryFrom<WireHash> for Hash {
    type Error = ConversionError;
    fn try_from(w: WireHash) -> Result<Self, Self::Error> {
        Ok(Hash::from_bytes(&w.0)?)
    }
}

impl TryFrom<&WireHash> for Hash {
    type Error = ConversionError;
    fn try_from(w: &WireHash) -> Result<Self, Self::Error> {
        Ok(Hash::from_bytes(&w.0)?)
    }
}

// ---------------------------------------------------------------------------
// Entity
//
// Byte-fidelity preserved: `data` is the CBOR payload as-is; the SDK side's
// Entity preserves it via `Vec<u8>` storage, and the wire side ships it
// through `#[serde(with = "serde_bytes")]`. content_hash travels on the
// wire (Q1 resolution) so neither side recomputes routinely.
// ---------------------------------------------------------------------------

impl From<Entity> for WireEntity {
    fn from(e: Entity) -> Self {
        WireEntity {
            entity_type: e.entity_type,
            data: e.data,
            content_hash: WireHash::from(e.content_hash),
        }
    }
}

impl From<&Entity> for WireEntity {
    fn from(e: &Entity) -> Self {
        WireEntity {
            entity_type: e.entity_type.clone(),
            data: e.data.clone(),
            content_hash: WireHash::from(e.content_hash),
        }
    }
}

impl TryFrom<WireEntity> for Entity {
    type Error = ConversionError;
    fn try_from(w: WireEntity) -> Result<Self, Self::Error> {
        Ok(Entity {
            entity_type: w.entity_type,
            data: w.data,
            content_hash: Hash::try_from(w.content_hash)?,
        })
    }
}

// ---------------------------------------------------------------------------
// ExecuteOptions
//
// Lossy in v1: only `resource.{targets,exclude}` cross the wire. Capability
// override, deliver_to, request_id, and bounds are not yet modeled because
// today's egui call sites don't use them (or their values are derived
// worker-side). Phase 2/3 may extend `WireExecuteOptions` if a consumer
// needs them.
// ---------------------------------------------------------------------------

impl From<&ExecuteOptions> for WireExecuteOptions {
    fn from(opts: &ExecuteOptions) -> Self {
        match &opts.resource {
            Some(rt) => WireExecuteOptions {
                resource_targets: rt.targets.clone(),
                resource_exclude: rt.exclude.clone(),
            },
            None => WireExecuteOptions::default(),
        }
    }
}

impl From<WireExecuteOptions> for ExecuteOptions {
    fn from(w: WireExecuteOptions) -> Self {
        let resource = if w.resource_targets.is_empty() && w.resource_exclude.is_empty() {
            None
        } else {
            Some(ResourceTarget {
                targets: w.resource_targets,
                exclude: w.resource_exclude,
            })
        };
        ExecuteOptions {
            resource,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// HandlerResult
// ---------------------------------------------------------------------------

impl From<HandlerResult> for WireHandlerResult {
    fn from(r: HandlerResult) -> Self {
        let included = r
            .included
            .into_iter()
            .map(|(h, e)| (WireHash::from(h), WireEntity::from(e)))
            .collect();
        WireHandlerResult {
            status: r.status,
            result: WireEntity::from(r.result),
            included,
        }
    }
}

impl TryFrom<WireHandlerResult> for HandlerResult {
    type Error = ConversionError;
    fn try_from(w: WireHandlerResult) -> Result<Self, Self::Error> {
        let mut included = HashMap::with_capacity(w.included.len());
        for (h, e) in w.included {
            included.insert(Hash::try_from(h)?, Entity::try_from(e)?);
        }
        Ok(HandlerResult {
            status: w.status,
            result: Entity::try_from(w.result)?,
            included,
        })
    }
}

// ---------------------------------------------------------------------------
// LocationEntry / WireListingEntry
// ---------------------------------------------------------------------------

impl From<LocationEntry> for WireListingEntry {
    fn from(e: LocationEntry) -> Self {
        WireListingEntry {
            path: e.path,
            content_hash: WireHash::from(e.hash),
        }
    }
}

impl TryFrom<WireListingEntry> for LocationEntry {
    type Error = ConversionError;
    fn try_from(w: WireListingEntry) -> Result<Self, Self::Error> {
        Ok(LocationEntry {
            path: w.path,
            hash: Hash::try_from(w.content_hash)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Query result types
// ---------------------------------------------------------------------------

impl From<entity_sdk::QueryMatch> for WireQueryMatch {
    fn from(m: entity_sdk::QueryMatch) -> Self {
        WireQueryMatch {
            path: m.path,
            content_hash: WireHash::from(m.content_hash),
            entity: m.entity.map(WireEntity::from),
            entity_type: m.entity_type,
        }
    }
}

impl From<entity_sdk::QueryResults> for WireQueryResults {
    fn from(q: entity_sdk::QueryResults) -> Self {
        WireQueryResults {
            matches: q.matches.into_iter().map(WireQueryMatch::from).collect(),
            has_more: q.has_more,
            total: q.total,
            cursor: q.cursor,
        }
    }
}

// ---------------------------------------------------------------------------
// PeerMetadata
// ---------------------------------------------------------------------------

impl From<entity_sdk::PeerMetadata> for WirePeerMetadata {
    fn from(m: entity_sdk::PeerMetadata) -> Self {
        WirePeerMetadata {
            label: m.label,
            persisted: m.persisted,
            listen_addresses: m.listen_addresses,
        }
    }
}

impl From<WirePeerMetadata> for entity_sdk::PeerMetadata {
    fn from(w: WirePeerMetadata) -> Self {
        entity_sdk::PeerMetadata {
            label: w.label,
            persisted: w.persisted,
            listen_addresses: w.listen_addresses,
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

impl From<entity_sdk::HandlerInfo> for WireHandlerInfo {
    fn from(h: entity_sdk::HandlerInfo) -> Self {
        WireHandlerInfo {
            pattern: h.pattern,
            name: h.name,
            operations: h.operations,
        }
    }
}

impl From<entity_sdk::FieldInfo> for WireFieldInfo {
    fn from(f: entity_sdk::FieldInfo) -> Self {
        WireFieldInfo {
            name: f.name,
            type_ref: f.type_ref,
            optional: f.optional,
        }
    }
}

impl From<entity_sdk::TypeInfo> for WireTypeInfo {
    fn from(t: entity_sdk::TypeInfo) -> Self {
        WireTypeInfo {
            type_path: t.type_path,
            fields: t.fields.into_iter().map(WireFieldInfo::from).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
//
// SdkError → WireError is a discriminant map (kind tag) plus carrying the
// error's display form as `message`. The reverse (WireError → SdkError) is
// not provided in v1 — the proxy receives WireError and surfaces it via
// `ProxyError`, which is the consumer's contract; we don't need to
// reconstruct an SdkError on the proxy side.
// ---------------------------------------------------------------------------

impl From<&entity_sdk::SdkError> for WireError {
    fn from(e: &entity_sdk::SdkError) -> Self {
        use entity_sdk::SdkError;
        // SdkError uses HTTP-style discriminants (BadRequest, Forbidden,
        // NotFound, Conflict, Internal, NotSupported) plus the typed
        // TreeError / HandlerError variants. Mapping is by intent, not
        // mechanical name match.
        let kind = match e {
            SdkError::NotFound { .. } => WireErrorKind::NotFound,
            SdkError::Forbidden { .. } => WireErrorKind::CapabilityDenied,
            SdkError::Conflict { .. } => WireErrorKind::Cas,
            SdkError::BadRequest { .. } => WireErrorKind::InvalidParams,
            SdkError::TreeError(_) => WireErrorKind::TreeError,
            SdkError::HandlerError(_) => WireErrorKind::HandlerError,
            // Catch-all for SdkError variants the protocol doesn't yet
            // model (Internal, NotSupported, setup-time errors like
            // NoKeypair / PeerBuild). Bumping PROTOCOL_VERSION + adding a
            // WireErrorKind variant is the right response if any of these
            // become load-bearing for cross-worker error handling.
            _ => WireErrorKind::Unknown,
        };
        WireError {
            kind,
            message: e.to_string(),
            detail: None,
        }
    }
}

impl From<entity_sdk::SdkError> for WireError {
    fn from(e: entity_sdk::SdkError) -> Self {
        WireError::from(&e)
    }
}

// ---------------------------------------------------------------------------
// CasFailure construction helpers
//
// SdkError doesn't carry a typed CasFailure value; CAS failures arise at
// the tree handler level. The host constructs CasFailure directly from the
// CAS result when calling `put_cas`, so we only provide construction
// helpers here, not From impls.
// ---------------------------------------------------------------------------

impl CasFailure {
    pub fn mismatch(actual: Hash) -> Self {
        Self {
            kind: CasFailureKind::Mismatch,
            actual: Some(WireHash::from(actual)),
        }
    }

    pub fn not_found() -> Self {
        Self {
            kind: CasFailureKind::NotFound,
            actual: None,
        }
    }
}
