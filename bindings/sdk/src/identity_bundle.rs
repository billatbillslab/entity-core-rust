//! Portable identity export — Layer 1 (the abstract Bundle) and
//! Layer 2 (`IdentityOps::export_bundle` / `restore_from_bundle`).
//!
//! ## Architecture
//!
//! Three-layer split:
//!
//! 1. **Abstract Bundle struct + CBOR serde** (this module). Cross-
//!    consumer portable bytes. The Bundle ships *entities* +
//!    *signatures* — not keypairs-plus-ceremony-rerun like
//!    workbench-go. Multi-signer bundles where the SDK never had the
//!    member keypairs (signatures came from other peers) still
//!    export.
//! 2. **SDK ops** (`export_bundle`, `restore_from_bundle`). Read +
//!    write the local peer's identity state; no IO.
//! 3. **Per-consumer storage adapter** — lives in each consumer
//!    crate (egui's `persistence.rs`, Tauri commands, etc.). Bytes
//!    in → wherever; wherever → bytes out. NOT this module.
//!
//! ## Cross-impl portability gap
//!
//! workbench-go's `IdentityBundle` is filesystem-shaped (keypairs +
//! manifest, ceremony re-mints entities). Bundle bytes do **not**
//! currently round-trip Go ↔ Rust. See
//! `docs/SPEC-AMBIGUITIES.md` § "IdentityBundle: Go filesystem-shape
//! vs eGUI entity-shape …" for the open architecture decision.
//! Interim: Rust ships entity-shape per the egui consumer ask.
//!
//! ## Restore preconditions
//!
//! `restore_from_bundle` requires the local peer's keypair to match
//! the public key carried by `bundle.identity_entity` (`system/peer`
//! data field `public_key`). Mismatched keypairs would silently produce
//! a peer claiming an identity it doesn't control; fail-closed with
//! `bundle_keypair_mismatch`.
//!
//! ## Private keys are NOT in the bundle
//!
//! Bundles carry only public material (the `system/peer` entity, its
//! quorums, attestations, signatures). The receiving peer MUST already
//! possess the matching keypair via a separate channel (the per-peer
//! keystore — `Keypair::save_to_file` / OPFS / app config dir, per
//! consumer). This is the spec §8.4a contract and the reason this
//! struct lacks a `keypair_*` field: a portable bundle is not a private-
//! key transport, and earlier revisions of this module that embedded
//! `keypair_pem` were rescinded as a security defect (bundle bytes
//! could leak the full Ed25519 secret to any consumer-side storage —
//! disk, cloud sync, screenshots, logs). The receiver's public-key
//! match is sufficient: only a peer holding the matching keypair can
//! actually use the restored identity to sign.
//!
//! ## Phase 1 scope (matches bootstrap Phase 1)
//!
//! - 1-of-1 self-quorum bundles round-trip cleanly: signer is the
//!   local peer, signature paths are derivable from the local
//!   `peer_id`, and the configure dispatch issues the controller
//!   cap.
//! - Multi-signer bundles can be **exported** (we capture the
//!   signatures regardless of who produced them), but **importing**
//!   one whose signatures live under non-local peer namespaces
//!   would need the bundle to carry the signer→peer_id mapping
//!   (Phase 2 work tracked when multi-signer bootstrap lands).

use crate::identity::{
    canonical_cert_path, future_boxed, path_internal_cert, path_public_cert,
    path_relationship_cert, read_contact_id_from_properties, read_mode_from_properties,
    IdentityOps,
};
use crate::identity_bootstrap::{
    bootstrap_status_owned, execute_owned, BootstrapInputs, BootstrapResult,
};
use crate::sdk::SdkError;
use ciborium::Value;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_types::{
    TYPE_ATTESTATION, TYPE_IDENTITY_PEER_CONFIG, TYPE_QUORUM, TYPE_SIGNATURE,
};

/// Current Bundle CBOR schema version. Bump on incompatible wire
/// changes; readers reject unknown versions.
///
/// **v2:** removed `keypair_pem` field. v1 bundles
/// embedded the full Ed25519 secret — a security defect. v1 readers
/// will reject v2 bundles and vice versa. No silent migration: any
/// v1 bytes in storage MUST be treated as compromised key material
/// and rotated; the receiving peer can re-export from its local
/// keystore to produce a v2 bundle.
const BUNDLE_SCHEMA_VERSION: u32 = 2;

/// Portable identity export. CBOR-serializable; same shape across
/// every consumer crate. See module-level doc for the architecture
/// split.
#[derive(Debug, Clone)]
pub struct IdentityBundle {
    /// Local peer's identity-entity content hash (V7 §3.6 — 33-byte
    /// `system/hash`). Pinned so `restore_from_bundle` can fail
    /// fast on keypair mismatch.
    pub identity_hash: Hash,
    /// The local peer's `system/peer` entity. Carries the public key
    /// in its data field (`{key_type, peer_id, public_key}` per
    /// `core/crypto::Keypair::peer_entity`); restore extracts that
    /// public key for the receiver-keypair-match precondition. No
    /// private bytes anywhere in this struct — see module docs.
    pub identity_entity: Entity,
    /// All quorum entities the identity stack depends on. For a
    /// bootstrap-1-of-1 export this is exactly one entry.
    pub quorums: Vec<Entity>,
    /// All identity-context attestation entities (controller cert,
    /// agent certs, identifier certs, etc.). Per-peer.
    pub attestations: Vec<Entity>,
    /// Signature entities backing the attestations. Each `target`
    /// field references an attestation hash; `signer` references a
    /// signer's identity hash.
    pub signatures: Vec<Entity>,
    /// Optional human label (echoed from `BootstrapOptions.label` or
    /// app-supplied).
    pub label: Option<String>,
    /// Caller-supplied opaque key-value pairs. SDK doesn't introspect.
    pub properties: Vec<(String, Value)>,
}

impl IdentityBundle {
    /// Serialize to deterministic CBOR. Same bytes for the same
    /// logical bundle on every run — caller can content-hash for
    /// integrity checks.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SdkError> {
        let value = self.to_cbor_value();
        let mut out = Vec::new();
        ciborium::ser::into_writer(&value, &mut out)
            .map_err(|e| SdkError::HandlerError(format!("bundle encode: {}", e)))?;
        Ok(out)
    }

    /// Deserialize from CBOR. Rejects unknown schema versions with
    /// `bundle_unsupported_version`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, SdkError> {
        let value: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| SdkError::HandlerError(format!("bundle decode: {}", e)))?;
        Self::from_cbor_value(&value)
    }

    /// Build the CBOR value with deterministic key ordering. Keys
    /// sorted alphabetically per ECF map convention so `to_cbor` is
    /// byte-stable.
    fn to_cbor_value(&self) -> Value {
        let mut fields: Vec<(Value, Value)> = Vec::new();
        fields.push((
            entity_ecf::text("attestations"),
            Value::Array(self.attestations.iter().map(entity_to_value).collect()),
        ));
        fields.push((
            entity_ecf::text("identity_entity"),
            entity_to_value(&self.identity_entity),
        ));
        fields.push((
            entity_ecf::text("identity_hash"),
            Value::Bytes(self.identity_hash.to_bytes().to_vec()),
        ));
        if let Some(label) = &self.label {
            fields.push((entity_ecf::text("label"), entity_ecf::text(label)));
        }
        if !self.properties.is_empty() {
            let props: Vec<(Value, Value)> = self
                .properties
                .iter()
                .map(|(k, v)| (entity_ecf::text(k), v.clone()))
                .collect();
            fields.push((entity_ecf::text("properties"), Value::Map(props)));
        }
        fields.push((
            entity_ecf::text("quorums"),
            Value::Array(self.quorums.iter().map(entity_to_value).collect()),
        ));
        fields.push((
            entity_ecf::text("schema_version"),
            entity_ecf::integer(BUNDLE_SCHEMA_VERSION as i64),
        ));
        fields.push((
            entity_ecf::text("signatures"),
            Value::Array(self.signatures.iter().map(entity_to_value).collect()),
        ));
        Value::Map(fields)
    }

    fn from_cbor_value(value: &Value) -> Result<Self, SdkError> {
        let map = value
            .as_map()
            .ok_or_else(|| SdkError::HandlerError("bundle: top-level not a map".into()))?;

        let mut schema_version: Option<u32> = None;
        let mut identity_hash: Option<Hash> = None;
        let mut identity_entity: Option<Entity> = None;
        let mut quorums: Vec<Entity> = Vec::new();
        let mut attestations: Vec<Entity> = Vec::new();
        let mut signatures: Vec<Entity> = Vec::new();
        let mut label: Option<String> = None;
        let mut properties: Vec<(String, Value)> = Vec::new();

        for (k, v) in map {
            match k.as_text() {
                Some("schema_version") => {
                    if let Value::Integer(i) = v {
                        let n: i128 = (*i).into();
                        if (0..=u32::MAX as i128).contains(&n) {
                            schema_version = Some(n as u32);
                        }
                    }
                }
                Some("identity_hash") => {
                    if let Value::Bytes(b) = v {
                        identity_hash = Hash::from_bytes(b).ok();
                    }
                }
                Some("keypair_pem") => {
                    // v1 carried this field (the security defect that
                    // v2 removed). Any bundle still presenting it is
                    // either v1 — rejected by the schema_version
                    // check below — or a forgery. Either way, do not
                    // decode it; the field has no v2 meaning.
                    return Err(SdkError::HandlerError(
                        "bundle: legacy v1 keypair_pem field present; v1 bundles leaked private keys and are unsupported in v2. Treat any v1 bundle bytes as compromised and re-export from the local keystore.".into(),
                    ));
                }
                Some("identity_entity") => identity_entity = value_to_entity(v).ok(),
                Some("quorums") => {
                    if let Value::Array(arr) = v {
                        for item in arr {
                            if let Ok(e) = value_to_entity(item) {
                                quorums.push(e);
                            }
                        }
                    }
                }
                Some("attestations") => {
                    if let Value::Array(arr) = v {
                        for item in arr {
                            if let Ok(e) = value_to_entity(item) {
                                attestations.push(e);
                            }
                        }
                    }
                }
                Some("signatures") => {
                    if let Value::Array(arr) = v {
                        for item in arr {
                            if let Ok(e) = value_to_entity(item) {
                                signatures.push(e);
                            }
                        }
                    }
                }
                Some("label") => label = v.as_text().map(|s| s.to_string()),
                Some("properties") => {
                    if let Value::Map(m) = v {
                        for (pk, pv) in m {
                            if let Some(s) = pk.as_text() {
                                properties.push((s.to_string(), pv.clone()));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let schema_version = schema_version
            .ok_or_else(|| SdkError::HandlerError("bundle: missing schema_version".into()))?;
        if schema_version != BUNDLE_SCHEMA_VERSION {
            return Err(SdkError::HandlerError(format!(
                "bundle_unsupported_version: bundle has schema_version={}, this SDK supports={}",
                schema_version, BUNDLE_SCHEMA_VERSION
            )));
        }

        Ok(IdentityBundle {
            identity_hash: identity_hash
                .ok_or_else(|| SdkError::HandlerError("bundle: missing identity_hash".into()))?,
            identity_entity: identity_entity
                .ok_or_else(|| SdkError::HandlerError("bundle: missing identity_entity".into()))?,
            quorums,
            attestations,
            signatures,
            label,
            properties,
        })
    }
}

/// Encode an Entity as a CBOR map `{type: text, data: bytes}`. The
/// `data` field carries the raw ECF-encoded bytes — bundle-roundtrip
/// preserves byte fidelity through `content_hash` recomputation on
/// import (no inline CBOR-of-CBOR shenanigans).
fn entity_to_value(entity: &Entity) -> Value {
    Value::Map(vec![
        (entity_ecf::text("data"), Value::Bytes(entity.data.clone())),
        (entity_ecf::text("type"), entity_ecf::text(&entity.entity_type)),
    ])
}

/// Reconstruct an Entity from the `{type, data}` bundle encoding.
/// `Entity::new` recomputes the content hash from `{type, data}`.
fn value_to_entity(value: &Value) -> Result<Entity, SdkError> {
    let map = value
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("bundle entity: not a map".into()))?;
    let mut etype: Option<String> = None;
    let mut edata: Option<Vec<u8>> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("type") => etype = v.as_text().map(|s| s.to_string()),
            Some("data") => {
                if let Value::Bytes(b) = v {
                    edata = Some(b.clone());
                }
            }
            _ => {}
        }
    }
    let etype = etype.ok_or_else(|| SdkError::HandlerError("bundle entity: missing type".into()))?;
    let edata = edata.ok_or_else(|| SdkError::HandlerError("bundle entity: missing data".into()))?;
    Entity::new(&etype, edata)
        .map_err(|e| SdkError::HandlerError(format!("bundle entity rebuild: {}", e)))
}

impl<'a> IdentityOps<'a> {
    /// Export the local peer's identity stack as a portable Bundle.
    /// Read-only — no state mutation.
    ///
    /// Returns 404 `not_bootstrapped` if the peer has no peer-config
    /// (call `bootstrap` first).
    ///
    /// The returned Bundle contains everything a fresh peer with the
    /// same keypair would need to reconstruct the identity:
    /// `system/peer` entity, all quorums, all identity-context
    /// attestations, all signatures, label, and caller-supplied
    /// properties.
    pub fn export_bundle(&self) -> Result<IdentityBundle, SdkError> {
        let ctx = self.ctx_ref();
        let pid = ctx.peer_id().to_string();

        // Pre-condition: peer must be bootstrapped (peer-config
        // present). Without it, there's nothing meaningful to export.
        let st = self.bootstrap_status();
        if !st.bootstrapped {
            return Err(SdkError::HandlerError(
                "export_bundle: not_bootstrapped — call bootstrap() first".into(),
            ));
        }

        let identity_hash = ctx.identity_hash();
        let store = ctx.store();
        let kp = ctx.peer().keypair();

        // Local peer entity — the source of identity_hash.
        let identity_entity = ctx
            .peer()
            .content_store()
            .get(&identity_hash)
            .or_else(|| {
                // If not in content store, mint from the keypair.
                // Same content hash since the entity is deterministic.
                kp.peer_entity().ok()
            })
            .ok_or_else(|| SdkError::HandlerError(
                "export_bundle: local peer entity unavailable".into(),
            ))?;

        // Walk subtrees. Each list returns paths; we resolve via
        // store.list_entities for path + entity pairs.
        let quorums = list_typed(
            &store,
            &format!("/{}/system/quorum/", pid),
            TYPE_QUORUM,
        );
        let mut attestations: Vec<Entity> = Vec::new();
        for sub in &[
            "system/identity/internal/cert/",
            "system/identity/public/cert/",
            "system/identity/relationships/",
        ] {
            attestations.extend(list_typed(
                &store,
                &format!("/{}/{}", pid, sub),
                TYPE_ATTESTATION,
            ));
        }
        let signatures = list_typed(
            &store,
            &format!("/{}/system/signature/", pid),
            TYPE_SIGNATURE,
        );

        // Read label from peer-config if present.
        let label = st
            .peer_config_path
            .as_deref()
            .and_then(|p| store.get(p))
            .and_then(|e| extract_label_from_peer_config(&e));

        Ok(IdentityBundle {
            identity_hash,
            identity_entity,
            quorums,
            attestations,
            signatures,
            label,
            properties: vec![],
        })
    }

    /// Restore an identity stack from a Bundle. Idempotent: re-running
    /// against an already-bootstrapped peer is safe because all writes
    /// are content-addressed and bindings to existing canonical paths
    /// are no-ops on identical content.
    ///
    /// **Precondition:** the local peer's keypair public bytes MUST
    /// match the `public_key` field carried by `bundle.identity_entity`
    /// (`system/peer` data). Mismatch returns `bundle_keypair_mismatch`
    /// — otherwise the restored peer would claim an identity it
    /// doesn't control.
    ///
    /// Bundles carry no private key material — the receiver must
    /// already possess the matching keypair via its own keystore
    /// (per-peer file / OPFS / app config dir). See module docs.
    ///
    /// Returns the same [`BootstrapResult`] shape as
    /// [`IdentityOps::bootstrap`] — the restore is logically a
    /// "bootstrap from existing state" rather than from scratch.
    /// Restore an identity stack from a Bundle. Returns a `'static`
    /// future so callers wiring through a `BoxFuture<'static, _>`
    /// trait method can drive it without cloning `PeerContext`.
    /// Captures the needed Arcs + the bundle (by clone) up front;
    /// runs the rest in an `async move` block. Mirrors the shape of
    /// [`IdentityOps::bootstrap`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn restore_from_bundle(
        &self,
        bundle: &IdentityBundle,
    ) -> impl std::future::Future<Output = Result<BootstrapResult, SdkError>> + Send + 'static
    {
        let inputs = BootstrapInputs::from_ctx(self.ctx_ref());
        let bundle = bundle.clone();
        future_boxed(run_restore_from_bundle(inputs, bundle))
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn restore_from_bundle(
        &self,
        bundle: &IdentityBundle,
    ) -> impl std::future::Future<Output = Result<BootstrapResult, SdkError>> + 'static {
        let inputs = BootstrapInputs::from_ctx(self.ctx_ref());
        let bundle = bundle.clone();
        future_boxed(run_restore_from_bundle(inputs, bundle))
    }
}

/// Run the restore ceremony against an owned [`BootstrapInputs`]
/// snapshot + an owned bundle. The async body owns its captures so
/// the returned future is `'static`.
async fn run_restore_from_bundle(
    inputs: BootstrapInputs,
    bundle: IdentityBundle,
) -> Result<BootstrapResult, SdkError> {
    let BootstrapInputs {
        shared,
        owner_cap,
        peer_id: pid,
        identity_hash: local_id,
        keypair,
        content_store: cs,
        location_index: li,
        tree,
    } = inputs;

    // Public-key-match precondition. Extract the peer entity's
    // public_key field (set by `Keypair::peer_entity` —
    // core/crypto/src/lib.rs §peer_entity) and compare to the
    // local keypair's public bytes. No private material involved.
    let bundle_public_key =
        extract_peer_public_key(&bundle.identity_entity).ok_or_else(|| {
            SdkError::HandlerError(
                "bundle: identity_entity missing public_key field".into(),
            )
        })?;
    if bundle_public_key != keypair.public_key_bytes() {
        return Err(SdkError::HandlerError(
            "bundle_keypair_mismatch: local peer's keypair does not match identity_entity public_key"
                .into(),
        ));
    }
    if bundle.identity_hash != local_id {
        return Err(SdkError::HandlerError(format!(
            "bundle_keypair_mismatch: bundle.identity_hash ({:?}) != local identity_hash ({:?})",
            bundle.identity_hash, local_id
        )));
    }

    // Short-circuit on already-bootstrapped: matches the
    // bootstrap idempotency shape.
    let st = bootstrap_status_owned(&pid, local_id, tree.as_ref());
    if st.bootstrapped {
        return Ok(BootstrapResult::AlreadyBootstrapped {
            identity_hash: local_id,
            quorum_id: st.quorum_id.ok_or_else(|| {
                SdkError::HandlerError(
                    "bundle restore: existing peer-config missing trusts_quorum".into(),
                )
            })?,
        });
    }

    // 1. Identity entity. Same content hash; put is idempotent.
    let _ = cs.put(bundle.identity_entity.clone());

    // 2. Quorum entities — content-addressed paths.
    let mut primary_quorum: Option<Hash> = None;
    for q in &bundle.quorums {
        let h = q.content_hash;
        cs.put(q.clone())
            .map_err(|e| SdkError::HandlerError(format!("restore quorum store: {}", e)))?;
        let path = format!("/{}/system/quorum/{}", pid, hex_segment(&h));
        li.set(&path, h);
        // First quorum is the bootstrap quorum (trusts_quorum).
        // For multi-quorum exports, callers may need to
        // dispatch additional configures; Phase 1 uses the first.
        if primary_quorum.is_none() {
            primary_quorum = Some(h);
        }
    }
    let primary_quorum = primary_quorum
        .ok_or_else(|| SdkError::HandlerError("bundle has no quorum entities".into()))?;

    // 3. Attestation entities — store first, bind after signatures
    //    (same ordering as bootstrap ceremony so process_attestation
    //    hook finds signatures already bound).
    for a in &bundle.attestations {
        cs.put(a.clone())
            .map_err(|e| SdkError::HandlerError(format!("restore attestation store: {}", e)))?;
    }

    // 4. Signature entities — store + bind. For Phase 1 (single-
    //    signer bundles), the signer IS the local peer, so the
    //    signature path uses the local peer_id. Multi-signer
    //    handling is a Phase 2 follow-up.
    for s in &bundle.signatures {
        let target_hash = extract_signature_target(s).ok_or_else(|| {
            SdkError::HandlerError("restore: signature entity malformed (no target)".into())
        })?;
        let h = cs
            .put(s.clone())
            .map_err(|e| SdkError::HandlerError(format!("restore signature store: {}", e)))?;
        let sig_path =
            format!("/{}/system/signature/{}", pid, hex_segment(&target_hash));
        li.set(&sig_path, h);
    }

    // 5. Bind each attestation at its canonical path (now that
    //    signatures are in place).
    let mut controller_cert: Option<Hash> = None;
    for a in &bundle.attestations {
        let props = extract_attestation_properties(a);
        let mode = read_mode_from_properties(&props);
        let contact_id = read_contact_id_from_properties(&props);
        let path = match mode {
            Some(m) => canonical_cert_path(m, contact_id, &a.content_hash),
            None => None,
        };
        // Phase 1: hard-code internal-tier when mode is missing
        // — Phase 1 bootstrap only mints internal-mode controller
        // certs anyway. The egui-bundle path for non-internal
        // attestations needs Phase 2 mode-aware export tests.
        let path = path.unwrap_or_else(|| path_internal_cert(&a.content_hash));
        let full = format!("/{}/{}", pid, path);
        li.set(&full, a.content_hash);
        // First controller-function attestation is the one configure
        // will use; we surface it in the result.
        if controller_cert.is_none()
            && extract_function(&props).as_deref() == Some("controller")
        {
            controller_cert = Some(a.content_hash);
        }
    }
    let controller_cert = controller_cert.ok_or_else(|| {
        SdkError::HandlerError(
            "restore: bundle has no controller-cert attestation".into(),
        )
    })?;

    // 6. Dispatch configure to mint the local peer→controller cap.
    //    Reuse bootstrap's configure-params shape. Wildcard grant
    //    matches Phase 1 default; consumers wanting narrower grants
    //    can call configure manually after restore.
    use entity_capability::{encode_grant_entry, GrantEntry, IdScope, PathScope};
    use entity_handler::ExecuteOptions;
    let grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["*".into()]),
        resources: PathScope::new(vec!["*".into()]),
        operations: IdScope::new(vec!["*".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let peer_config_path = format!("/{}/system/identity/peer-config", pid);
    let params_data = entity_ecf::to_ecf(&Value::Map(vec![
        (
            entity_ecf::text("controller_grants"),
            Value::Array(grants.iter().map(encode_grant_entry).collect()),
        ),
        (
            entity_ecf::text("trusts_quorum"),
            Value::Bytes(primary_quorum.to_bytes().to_vec()),
        ),
    ]));
    let params = Entity::new("primitive/any", params_data)
        .map_err(|e| SdkError::HandlerError(format!("restore params encode: {}", e)))?;
    let opts = ExecuteOptions {
        resource: Some(entity_capability::ResourceTarget {
            targets: vec![peer_config_path.clone()],
            exclude: vec![],
        }),
        ..Default::default()
    };
    let result = execute_owned(
        shared,
        owner_cap,
        "system/identity",
        "configure",
        params,
        opts,
    )
    .await?;
    if let Some(err) = SdkError::from_handler_result(&result, "restore: configure") {
        return Err(err);
    }
    let issued_caps = extract_issued_caps(&result.result);

    Ok(BootstrapResult::Bootstrapped {
        identity_hash: local_id,
        quorum_id: primary_quorum,
        controller_cert,
        peer_config_path,
        issued_caps,
    })
}

// --- helpers ---

fn hex_segment(h: &Hash) -> String {
    let bytes = h.to_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Scan a tree prefix for entities of a given type. Drops paths
/// whose entity isn't bound in the content store (defensive) or
/// whose type doesn't match. Order is whatever the location index
/// returns; the bundle CBOR encoding doesn't depend on order beyond
/// the surrounding deterministic sort.
fn list_typed(
    store: &crate::sdk::StoreAccess<'_>,
    prefix: &str,
    expected_type: &str,
) -> Vec<Entity> {
    store
        .list_entities(prefix)
        .into_iter()
        .filter_map(|(_path, e)| {
            if e.entity_type == expected_type {
                Some(e)
            } else {
                None
            }
        })
        .collect()
}

fn extract_label_from_peer_config(entity: &Entity) -> Option<String> {
    // peer-config doesn't carry a label field directly today. We
    // surface the quorum's label via a quorum lookup if needed; for
    // Phase 1, return None and let consumers thread their own label
    // via `IdentityBundle.label` after the export call.
    let _ = entity.entity_type == TYPE_IDENTITY_PEER_CONFIG;
    None
}

fn extract_peer_public_key(entity: &Entity) -> Option<[u8; 32]> {
    let val: Value = ciborium::de::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("public_key") {
            if let Value::Bytes(b) = v {
                if b.len() == 32 {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(b);
                    return Some(out);
                }
            }
        }
    }
    None
}

fn extract_signature_target(entity: &Entity) -> Option<Hash> {
    let val: Value = ciborium::de::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("target") {
            if let Value::Bytes(b) = v {
                return Hash::from_bytes(b).ok();
            }
        }
    }
    None
}

fn extract_attestation_properties(entity: &Entity) -> Vec<(Value, Value)> {
    let val: Value = match ciborium::de::from_reader(entity.data.as_slice()) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let map = match val.as_map() {
        Some(m) => m,
        None => return Vec::new(),
    };
    for (k, v) in map {
        if k.as_text() == Some("properties") {
            if let Value::Map(m) = v {
                return m.clone();
            }
        }
    }
    Vec::new()
}

fn extract_function(properties: &[(Value, Value)]) -> Option<String> {
    for (k, v) in properties {
        if k.as_text() == Some("function") {
            return v.as_text().map(|s| s.to_string());
        }
    }
    None
}

fn extract_issued_caps(entity: &Entity) -> Vec<Hash> {
    let val: Value = match ciborium::de::from_reader(entity.data.as_slice()) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let map = match val.as_map() {
        Some(m) => m,
        None => return Vec::new(),
    };
    for (k, v) in map {
        if k.as_text() == Some("local_peer_to_controller_caps") {
            if let Value::Array(arr) = v {
                return arr
                    .iter()
                    .filter_map(|item| match item {
                        Value::Bytes(b) => Hash::from_bytes(b).ok(),
                        _ => None,
                    })
                    .collect();
            }
        }
    }
    Vec::new()
}

// Suppress unused-import on path_public_cert / path_relationship_cert
// until non-internal mode is exercised — they're crate-public for the
// canonical path lookup. `path_internal_cert` is consumed in the
// fallback above.
#[allow(dead_code)]
fn _suppress_unused() {
    let h = Hash::from_bytes(&[0u8; 33]).unwrap();
    let _ = path_public_cert(&h);
    let _ = path_relationship_cert(&h, &h);
}

/// Build-time contract check: `restore_from_bundle` returns a future
/// that can be moved into a `Pin<Box<dyn Future + Send + 'static>>` —
/// the shape `PeerBinding::restore_identity_bundle` needs. Companion
/// to `bootstrap_future_is_static_send` in identity_bootstrap.rs.
///
/// Native-only — the wasm32 variant of `restore_from_bundle`
/// intentionally drops the `Send` bound (single-threaded JS runtime).
#[allow(dead_code)]
#[cfg(not(target_arch = "wasm32"))]
fn restore_future_is_static_send(
    ctx: &crate::sdk::PeerContext,
    bundle: &IdentityBundle,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<BootstrapResult, SdkError>> + Send + 'static>,
> {
    Box::pin(ctx.identity().restore_from_bundle(bundle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_bootstrap::BootstrapOptions;
    use crate::sdk::{PeerContext, PeerContextBuilder};
    // Test-only: validates that PEM-based keypair transfer (the
    // legitimate out-of-band path) still works as the restore
    // counterpart. Production code in this module has no PEM dep.
    use entity_crypto::Keypair;

    fn make_ctx() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    /// Export on a non-bootstrapped peer is rejected.
    #[test]
    fn export_pre_bootstrap_fails() {
        let ctx = make_ctx();
        let r = ctx.identity().export_bundle();
        match r {
            Err(SdkError::HandlerError(msg)) if msg.contains("not_bootstrapped") => {}
            other => panic!("expected not_bootstrapped, got {:?}", other),
        }
    }

    /// Round-trip: bootstrap → export → CBOR → from_cbor decodes
    /// to a Bundle with the same identity_hash + non-empty entity
    /// arrays.
    #[tokio::test(flavor = "current_thread")]
    async fn export_then_cbor_roundtrip() {
        let ctx = make_ctx();
        let _ = ctx
            .identity()
            .bootstrap(BootstrapOptions::default())
            .await
            .expect("bootstrap");

        let bundle = ctx.identity().export_bundle().expect("export");
        assert_eq!(bundle.identity_hash, ctx.identity_hash());
        assert_eq!(bundle.identity_entity.entity_type, "system/peer");
        assert!(!bundle.quorums.is_empty(), "1-of-1 bootstrap → 1 quorum");
        assert!(
            !bundle.attestations.is_empty(),
            "bootstrap → 1 controller cert"
        );
        assert!(!bundle.signatures.is_empty(), "1-of-1 → 1 signature");

        // v2: no private material in the serialized bytes. The Ed25519
        // secret key is 32 bytes; verify no 32-byte substring of the
        // encoded bundle equals the keypair's secret bytes.
        let bytes = bundle.to_cbor().expect("encode");
        let secret = ctx
            .peer()
            .keypair()
            .as_ed25519()
            .expect("SDK test peer is Ed25519")
            .secret_key_bytes();
        let has_secret = bytes.windows(32).any(|w| w == secret);
        assert!(
            !has_secret,
            "v2 bundle bytes MUST NOT contain the Ed25519 secret key"
        );

        let reloaded = IdentityBundle::from_cbor(&bytes).expect("decode");
        assert_eq!(reloaded.identity_hash, bundle.identity_hash);
        assert_eq!(reloaded.quorums.len(), bundle.quorums.len());
        assert_eq!(reloaded.attestations.len(), bundle.attestations.len());
        assert_eq!(reloaded.signatures.len(), bundle.signatures.len());
        for (a, b) in reloaded.quorums.iter().zip(&bundle.quorums) {
            assert_eq!(a.content_hash, b.content_hash);
        }
    }

    /// from_cbor with a wrong schema_version reports a clear error.
    #[test]
    fn from_cbor_rejects_unknown_version() {
        let bad = ciborium::Value::Map(vec![(
            entity_ecf::text("schema_version"),
            entity_ecf::integer(999),
        )]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&bad, &mut bytes).unwrap();
        let r = IdentityBundle::from_cbor(&bytes);
        match r {
            Err(SdkError::HandlerError(msg)) if msg.contains("bundle_unsupported_version") => {}
            other => panic!("expected unsupported_version, got {:?}", other),
        }
    }

    /// restore_from_bundle rejects a bundle whose identity_entity
    /// public_key doesn't match the local peer's keypair.
    #[tokio::test(flavor = "current_thread")]
    async fn restore_rejects_keypair_mismatch() {
        let ctx_a = make_ctx();
        let _ = ctx_a
            .identity()
            .bootstrap(BootstrapOptions::default())
            .await
            .expect("bootstrap A");
        let bundle = ctx_a.identity().export_bundle().expect("export A");

        // Different peer (different keypair); same bundle.
        let ctx_b = make_ctx();
        let r = ctx_b.identity().restore_from_bundle(&bundle).await;
        match r {
            Err(SdkError::HandlerError(msg)) if msg.contains("bundle_keypair_mismatch") => {}
            other => panic!("expected bundle_keypair_mismatch, got {:?}", other),
        }
    }

    /// restore on an already-bootstrapped peer returns AlreadyBootstrapped.
    #[tokio::test(flavor = "current_thread")]
    async fn restore_already_bootstrapped_short_circuits() {
        let ctx = make_ctx();
        let _ = ctx
            .identity()
            .bootstrap(BootstrapOptions::default())
            .await
            .expect("bootstrap");
        let bundle = ctx.identity().export_bundle().expect("export");
        let r = ctx
            .identity()
            .restore_from_bundle(&bundle)
            .await
            .expect("idempotent restore");
        match r {
            BootstrapResult::AlreadyBootstrapped { identity_hash, .. } => {
                assert_eq!(identity_hash, ctx.identity_hash());
            }
            other => panic!("expected AlreadyBootstrapped, got {:?}", other),
        }
    }

    /// Full ceremony round-trip: bootstrap on peer A → export → CBOR →
    /// fresh peer B with the same keypair → from_cbor → restore →
    /// peer B is now bootstrapped with the same quorum_id and
    /// controller_cert hashes.
    #[tokio::test(flavor = "current_thread")]
    async fn full_restore_round_trip_same_keypair_fresh_peer() {
        let ctx_a = make_ctx();
        let kp_pem = ctx_a.peer().keypair().to_pem();
        let bres_a = ctx_a
            .identity()
            .bootstrap(BootstrapOptions::default())
            .await
            .expect("bootstrap A");
        let (qid_a, cert_a) = match bres_a {
            BootstrapResult::Bootstrapped {
                quorum_id,
                controller_cert,
                ..
            } => (quorum_id, controller_cert),
            other => panic!("expected Bootstrapped, got {:?}", other),
        };
        let bundle = ctx_a.identity().export_bundle().expect("export A");
        let bundle_bytes = bundle.to_cbor().expect("encode");

        // Peer B: same keypair, fresh tree. Reconstruct via the
        // builder + restore_from_bundle.
        let kp_b = Keypair::from_pem(&kp_pem).expect("pem decode");
        let ctx_b = PeerContextBuilder::new()
            .keypair(kp_b)
            .build()
            .expect("ctx B build");
        let reloaded = IdentityBundle::from_cbor(&bundle_bytes).expect("decode");
        let bres_b = ctx_b
            .identity()
            .restore_from_bundle(&reloaded)
            .await
            .expect("restore B");
        match bres_b {
            BootstrapResult::Bootstrapped {
                identity_hash,
                quorum_id,
                controller_cert,
                ..
            } => {
                assert_eq!(identity_hash, ctx_b.identity_hash());
                assert_eq!(identity_hash, ctx_a.identity_hash());
                assert_eq!(
                    quorum_id, qid_a,
                    "restored quorum_id matches original"
                );
                assert_eq!(
                    controller_cert, cert_a,
                    "restored controller_cert matches original"
                );
            }
            other => panic!("expected Bootstrapped, got {:?}", other),
        }
        // Status confirms.
        let st = ctx_b.identity().bootstrap_status();
        assert!(st.bootstrapped);
        assert_eq!(st.quorum_id, Some(qid_a));
    }
}
