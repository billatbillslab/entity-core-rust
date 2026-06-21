//! Cross-peer chain capability mint + bundle, per
//! `EXTENSION-CONTINUATION §4.2 case 3 / §8.2 C-3` (the re-attenuation
//! mint shape for cross-peer continuation dispatch caps).
//!
//! ## What this module does
//!
//! Two operations needed when the local peer installs a continuation
//! whose target is a REMOTE peer:
//!
//! 1. **`mint_cross_peer_chain_capability`** — mints a dispatch
//!    capability suitable as the continuation's `dispatch_capability`.
//!    The minted authority chain shape:
//!
//!    ```text
//!    leaf (granter=local, grantee=local, parent=connCap)
//!      └─ connCap (granter=B, grantee=local, parent=nil)
//!                    ← B-rooted root
//!    ```
//!
//!    where `B` is the remote peer identified by `remote_peer_id` and
//!    `connCap` is the connection grant B conferred during the connect
//!    handshake.
//!
//! 2. **`bundle_cross_peer_chain`** — assembles the full set of
//!    entities the remote verifier needs to validate the leaf cap's
//!    authority chain end-to-end: every cap from leaf to root, plus
//!    each link's granter identity entity and detached signature
//!    (resolved from the V7 §3.5 invariant pointer path). Per
//!    `EXTENSION-CONTINUATION §4.3` the bundle MUST be in the
//!    dispatched EXECUTE envelope's `included`.
//!
//! ## Why this shape
//!
//! Per Go SDK convergence reference (`workbench-go/entitysdk/cross_peer_cap_mint.go`):
//!
//! - **B-rooted, not installer-rooted.** Chain must root at B's
//!   conferred authority so B's advance-time `verify_chain` succeeds.
//!   An installer-rooted chain is the local-sufficient form that
//!   fails cross-peer (v1.9 / pre-Amendment-4 collapse).
//! - **Installer in-chain.** The §3.1a / §3.2-step-4 install-time
//!   in-chain check requires the writer (installer) to appear as a
//!   granter anywhere in the chain. Mint as re-attenuation: installer
//!   is the leaf granter, in-chain trivially.
//! - **Grantee = dispatching host peer (EXECUTE author).** §4.2 case
//!   3 (iii). Self-wielding to the installer is the v1.9 gap
//!   Amendment B closes with `grantee != author`. For the workbench
//!   typical case this is moot (both are local), but the API forces
//!   the right identity in both slots so callers don't drift.

use crate::sdk::{PeerContext, SdkError};
use entity_capability::{GrantEntry, MintError};
use entity_entity::Entity;
use entity_hash::Hash;

impl PeerContext {
    /// Mint a dispatch capability suitable as the `dispatch_capability`
    /// on a continuation step whose target is `remote_peer_id`.
    ///
    /// Pre-condition: the local peer must hold an open connection to
    /// `remote_peer_id` (call `connect` first). The connection grant
    /// B conferred during handshake is the chain root.
    ///
    /// Persistence: the minted cap + signature are written to the
    /// local content store. The signature is additionally bound at
    /// the V7 §3.5 invariant pointer path so
    /// [`bundle_cross_peer_chain`](Self::bundle_cross_peer_chain) can
    /// resolve it the same way envelope-ingest resolves B's signature
    /// on the connection grant.
    ///
    /// Returns the leaf cap entity. Caller obtains the full chain +
    /// signature bundle via `bundle_cross_peer_chain(leaf)` and
    /// bundles the result into the dispatched EXECUTE envelope's
    /// `included` per §4.3.
    ///
    /// Matches Go SDK's `AppPeer.MintCrossPeerChainCapability`
    /// (`workbench-go/entitysdk/cross_peer_cap_mint.go:61`).
    pub fn mint_cross_peer_chain_capability(
        &self,
        remote_peer_id: &str,
        grants: Vec<GrantEntry>,
        expires_at: Option<u64>,
    ) -> Result<Entity, SdkError> {
        if remote_peer_id.is_empty() {
            return Err(SdkError::HandlerError(
                "mint_cross_peer_chain_capability requires remote_peer_id".into(),
            ));
        }
        if grants.is_empty() {
            return Err(SdkError::HandlerError(
                "mint_cross_peer_chain_capability requires at least one grant entry".into(),
            ));
        }

        // Look up the active connection to `remote_peer_id`. The
        // RemoteConnection's `capability` is the connection grant B
        // conferred during handshake — the chain root.
        let conn = match self.shared.remote.get(remote_peer_id) {
            Some(c) => c,
            None => {
                return Err(SdkError::HandlerError(format!(
                    "mint_cross_peer_chain_capability: no connection-grant on file for {} — connect() first",
                    remote_peer_id
                )));
            }
        };
        // After R1's pool refactor the pool entry is `Arc<dyn RemoteEndpoint>`
        // — `capability` is a trait method now, not a field.
        let parent_cap = conn.capability().clone();

        // Persist the parent cap defensively. Envelope-ingest on
        // PerformConnect persists the granter identity + signature
        // at the invariant path, but only re-encodes the cap entity
        // when CollectChainBundle needs it; making the entity
        // reachable from the store here is cheap and removes a
        // bundle-time precondition.
        if self.shared.content_store.get(&parent_cap.content_hash).is_none() {
            self.shared
                .content_store
                .put(parent_cap.clone())
                .map_err(|e| {
                    SdkError::HandlerError(format!("persist parent connection-grant: {}", e))
                })?;
        }

        // Load the local identity entity (mint_reattenuated needs the
        // entity, not just the hash, for the signer_identity slot).
        let local_identity_hash = self.shared.identity_hash;
        let local_identity_entity = self
            .shared
            .content_store
            .get(&local_identity_hash)
            .ok_or_else(|| {
                SdkError::HandlerError(
                    "mint_cross_peer_chain_capability: local identity entity not in content store"
                        .into(),
                )
            })?;

        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let (cap_entity, sig_entity) = entity_capability::mint_reattenuated(
            self.shared
                .keypair
                .as_ed25519()
                .expect("entity-sdk peers are Ed25519-only (Ed448 backends use core PeerBuilder)"),
            &local_identity_entity,
            local_identity_hash, // grantee = dispatching host peer (same as installer locally)
            &parent_cap,
            grants,
            now_ms,
            expires_at,
        )
        .map_err(|e| SdkError::HandlerError(format!("mint_reattenuated: {}", mint_err_msg(&e))))?;

        self.shared
            .content_store
            .put(cap_entity.clone())
            .map_err(|e| SdkError::HandlerError(format!("persist re-attenuated cap: {}", e)))?;
        self.shared
            .content_store
            .put(sig_entity.clone())
            .map_err(|e| {
                SdkError::HandlerError(format!("persist re-attenuated cap signature: {}", e))
            })?;

        // Bind our own signature at the V7 §3.5 invariant pointer
        // path so bundle_cross_peer_chain can find it.
        let local_peer_id_str = self.peer_id().to_string();
        let sig_path =
            entity_hash::invariant_signature_path(&local_peer_id_str, &cap_entity.content_hash);
        if let Some(existing) = self.shared.location_index.get(&sig_path) {
            if existing != sig_entity.content_hash {
                return Err(SdkError::HandlerError(format!(
                    "invariant signature path {} already bound to a different hash",
                    sig_path
                )));
            }
            // Same hash → idempotent re-mint; nothing to do.
        } else {
            self.shared
                .location_index
                .set(&sig_path, sig_entity.content_hash);
        }

        Ok(cap_entity)
    }

    /// Assemble the full set of entities the remote verifier needs to
    /// validate `leaf_cap`'s authority chain end-to-end — every cap
    /// from leaf to root, plus each link's granter identity entity
    /// and detached signature.
    ///
    /// Per `EXTENSION-CONTINUATION §4.3`, this bundle MUST be in the
    /// dispatched EXECUTE envelope's `included`. The V7 §3.1/§3.2
    /// general rule only carries the leaf cap (referenced from
    /// EXECUTE data); the transitive chain is referenced from
    /// **within** the cap entities and must be bundled explicitly.
    ///
    /// Over-inclusion is intentional and free: content-addressing
    /// dedups any entity the verifier already holds. Best-effort per
    /// link — a link whose signature or granter identity isn't
    /// locally resolvable is silently omitted; the verifier
    /// fails-closed at use time if it actually needed it.
    ///
    /// Matches Go SDK's `AppPeer.BundleCrossPeerChain`
    /// (`workbench-go/entitysdk/cross_peer_cap_mint.go:162`).
    pub fn bundle_cross_peer_chain(
        &self,
        leaf_cap: &Entity,
    ) -> Result<std::collections::HashMap<Hash, Entity>, SdkError> {
        let mut bundle: std::collections::HashMap<Hash, Entity> =
            std::collections::HashMap::new();

        // Walk the chain leaf → parent → ... until we hit a cap with
        // no parent (root). Capping the depth prevents a malformed
        // chain from spinning the walker.
        let mut current = leaf_cap.clone();
        for _ in 0..64 {
            // Insert the cap entity itself.
            bundle.insert(current.content_hash, current.clone());

            // Decode the cap to find the granter identity (for the
            // signature path) and the parent link.
            let token = match entity_capability::CapabilityToken::from_entity(&current) {
                Ok(t) => t,
                Err(_) => break, // Malformed cap; stop the walk.
            };

            // Granter identity entity, when resolvable.
            let granter_hash = match &token.granter {
                entity_capability::Granter::Single(h) => Some(*h),
                _ => None, // Multi-sig granters lookup is different; skip for now.
            };
            if let Some(gh) = granter_hash {
                if let Some(identity_entity) = self.shared.content_store.get(&gh) {
                    bundle.insert(gh, identity_entity.clone());

                    // Detached signature at the invariant path. V7 §1.5
                    // v7.65: derive canonical wire peer_id from
                    // (public_key, key_type) — entity no longer carries it.
                    if let Ok(granter_peer_data) = entity_types::PeerData::from_entity(&identity_entity) {
                        if let Some(granter_peer_id) = granter_peer_data.canonical_peer_id() {
                            let sig_path = entity_hash::invariant_signature_path(
                                &granter_peer_id,
                                &current.content_hash,
                            );
                            if let Some(sig_hash) = self.shared.location_index.get(&sig_path) {
                                if let Some(sig_entity) = self.shared.content_store.get(&sig_hash) {
                                    bundle.insert(sig_hash, sig_entity);
                                }
                            }
                        }
                    }
                }
            }

            // Step up to the parent.
            match token.parent {
                Some(parent_hash) => {
                    match self.shared.content_store.get(&parent_hash) {
                        Some(parent_ent) => current = parent_ent,
                        None => break, // Parent not resolvable locally; stop the walk.
                    }
                }
                None => break, // Reached root.
            }
        }

        Ok(bundle)
    }
}

fn mint_err_msg(e: &MintError) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::PeerContextBuilder;
    use entity_capability::{IdScope, PathScope};

    fn make_ctx() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    fn sample_grants() -> Vec<GrantEntry> {
        vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["app/notes/*".into()]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }]
    }

    /// Empty remote_peer_id rejected with a wrapper-shaped error
    /// before any connection lookup runs.
    #[test]
    fn mint_cross_peer_chain_empty_remote_rejects() {
        let ctx = make_ctx();
        let r = ctx.mint_cross_peer_chain_capability("", sample_grants(), None);
        assert!(matches!(r, Err(SdkError::HandlerError(_))));
    }

    /// Empty grants rejected pre-lookup, matching Go's 400
    /// invalid_grants.
    #[test]
    fn mint_cross_peer_chain_empty_grants_rejects() {
        let ctx = make_ctx();
        let r = ctx.mint_cross_peer_chain_capability("some-peer", vec![], None);
        assert!(matches!(r, Err(SdkError::HandlerError(_))));
    }

    /// No connection on file → 404-shaped error citing the missing
    /// peer-id. Documents the precondition that connect() must run
    /// before MintCrossPeerChain.
    #[test]
    fn mint_cross_peer_chain_no_connection_returns_error() {
        let ctx = make_ctx();
        let r = ctx.mint_cross_peer_chain_capability(
            "unconnected-peer-id",
            sample_grants(),
            None,
        );
        match r {
            Err(SdkError::HandlerError(msg)) if msg.contains("no connection-grant") => {}
            other => panic!("expected no connection-grant error, got {:?}", other),
        }
    }

    /// `bundle_cross_peer_chain` on a single-link cap (no parent)
    /// returns a bundle containing just the cap itself (and the
    /// granter identity if available locally — for the local
    /// self-cap minted by PeerContextBuilder, it should be).
    #[test]
    fn bundle_cross_peer_chain_self_cap_round_trips() {
        let ctx = make_ctx();
        // Mint a local scoped self-cap (not cross-peer — we just
        // need a CapabilityToken to walk).
        let cap_entity = ctx
            .mint_chain_capability(sample_grants())
            .expect("local mint should succeed");
        let bundle = ctx
            .bundle_cross_peer_chain(&cap_entity)
            .expect("bundle walk should succeed");
        assert!(
            bundle.contains_key(&cap_entity.content_hash),
            "bundle includes the leaf cap entity itself"
        );
        // Granter identity is the local peer — should be in the
        // content store, hence the bundle.
        assert!(
            bundle.contains_key(&ctx.identity_hash()),
            "bundle includes the granter identity entity"
        );
    }
}
