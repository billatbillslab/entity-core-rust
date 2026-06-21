//! §3.5 inbox-relay resolution seam (the MX-record lookup).
//!
//! The §6.2.1 Mode-F→Mode-S fallback needs to know *where* to store mail for an
//! unreachable destination. §3.5 answers this with a published, signed
//! `system/peer/inbox-relay` declaration served always-on by REGISTRY. Looking
//! it up is a cross-peer resolution that belongs to the wiring layer (REGISTRY
//! integration lives in `core/peer`), so the relay handler depends only on this
//! trait — mirroring Go's `InboxRelayResolver` interface + `NopInboxRelayResolver`
//! default.
//!
//! **Trust:** the declaration is self-certifying (signed by the destination's
//! key, §4). A resolver implementation MUST verify the signature against the
//! destination peer-id before returning it (fail-closed on mismatch) — an
//! untrusted holder cannot redirect a victim's mail. The `Nop` default returns
//! nothing, so the handler takes the default convention or surfaces
//! `no_inbox_relay`.

use std::sync::Arc;

use entity_crypto::{peer_identity_hash_with_key_type, verify_for_key_type, KeyType, PeerId};
use entity_hash::invariant_signature_path;
use entity_store::{ContentStore, LocationIndex};
use entity_types::SignatureData;

use crate::data::InboxRelayData;
use crate::inbox_relay_path;

/// Resolves a destination's §3.5 inbox-relay declaration. Implemented over
/// REGISTRY (the always-on home) in `core/peer`; the default is a no-op.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait InboxRelayResolver: Send + Sync {
    /// Return `destination`'s verified inbox-relay declaration, or `None` if it
    /// declared none (or could not be resolved/verified).
    async fn resolve(&self, destination: &str) -> Option<InboxRelayData>;
}

/// Default resolver: resolves nothing. With it, the handler relies on the
/// default-convention fallback (namespace = destination peer-id) unless that is
/// disabled, in which case `:forward` surfaces `no_inbox_relay`/502.
pub struct NopInboxRelayResolver;

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl InboxRelayResolver for NopInboxRelayResolver {
    async fn resolve(&self, _destination: &str) -> Option<InboxRelayData> {
        None
    }
}

/// Tree-backed §3.5 inbox-relay resolver — reads the declaration from the
/// local peer's tree and applies the **forged-redirection defense** (§3.5 /
/// V7 §5.2): the declaration is returned only if its invariant-pointer
/// signature verifies against the *destination peer's own* key. An attacker
/// who plants a declaration signed by any other key cannot redirect a victim's
/// mail — `resolve` falls closed (returns `None`) on any failure, never a
/// silently-trusted declaration. Mirrors Go's `TreeInboxRelayResolver`.
///
/// **v1 simplification (matches Go):** the canonical primary holder per §3.5 is
/// REGISTRY (always-on); v1 reads the peer's own tree (where the cohort fixture
/// publishes the declaration + its signature). Production wiring would chain
/// through REGISTRY before this local-tree fallback. The lookup *shape* — path
/// resolve → fetch decl → fetch signature → derive key from peer-id → verify —
/// is identical regardless of authority origin.
pub struct TreeInboxRelayResolver {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    /// The namespace lookups are anchored under (all `LocationIndex` paths are
    /// absolute: `/{local_peer_id}/...`).
    local_peer_id: String,
}

impl TreeInboxRelayResolver {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        Self {
            content_store,
            location_index,
            local_peer_id,
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl InboxRelayResolver for TreeInboxRelayResolver {
    async fn resolve(&self, destination: &str) -> Option<InboxRelayData> {
        if destination.is_empty() {
            return None;
        }

        // 1) Resolve the declaration at the peer-local form
        //    /{local_peer_id}/system/peer/inbox-relay/{destination}.
        let decl_path = format!("/{}/{}", self.local_peer_id, inbox_relay_path(destination));
        let decl_hash = self.location_index.get(&decl_path)?;
        let decl_entity = self.content_store.get(&decl_hash)?;

        // 2) Decode + type-check (from_entity enforces TYPE_PEER_INBOX_RELAY).
        let decl = InboxRelayData::from_entity(&decl_entity).ok()?;

        // 3) Locate the V7 §5.2 invariant-pointer signature over the declaration.
        //    The destination signed it; the signature is bound at the
        //    destination's pointer. Try the local namespace first (where the
        //    fixture replicates for our view), then the destination's namespace
        //    (REGISTRY would replicate under the publisher's authority).
        let sig_hash = self
            .location_index
            .get(&invariant_signature_path(&self.local_peer_id, &decl_hash))
            .or_else(|| {
                self.location_index
                    .get(&invariant_signature_path(destination, &decl_hash))
            })?;
        let sig_entity = self.content_store.get(&sig_hash)?;
        let sig = SignatureData::from_entity(&sig_entity).ok()?;
        if sig.target != decl_hash {
            return None;
        }

        // 4) Derive the destination's (public_key, key_type) from its peer-id
        //    (v7.64 identity-multihash form is self-describing). SHA-256-form
        //    peer-ids carry no embedded key → fall closed (the common cohort
        //    case is identity-form).
        let (public_key, key_type_byte) = PeerId::from(destination).derive_public_key()?;
        let key_type = KeyType::from_byte(key_type_byte).ok()?;

        // 5) Cross-check: the signer identity-hash MUST equal the destination's
        //    canonical identity hash — i.e. the destination really signed it,
        //    not a look-alike peer.
        let dest_identity_hash = peer_identity_hash_with_key_type(&public_key, key_type).ok()?;
        if sig.signer != dest_identity_hash {
            return None;
        }

        // 6) V7 §5.2 fail-closed signature verification over the declaration's
        //    content hash bytes.
        verify_for_key_type(key_type, &public_key, &decl_hash.to_bytes(), &sig.signature).ok()?;

        Some(decl)
    }
}
