//! §10 rotation + §11 revocation — Tier-A (V7-floor) entity types and the
//! §4.4/§10.1/§11.1 resolution logic.
//!
//! **Trust seam.** Tier-A authority lives in V7 `system/signature` invariant
//! pointers: the pubkey publication (§4.2.a), the dual-signed handoff (§10.1),
//! and the V7-signed revocation (§11.1). Verifying those signatures requires
//! the peer's keystore + tree and is the handler layer's job — the same seam
//! peer-mode sender-auth (§7.4) uses. The pure functions here operate over
//! entities the caller has ALREADY signature-verified, implementing the
//! spec's mechanical part: walk the handoff chain forward to the terminal
//! pubkey, then reject if it carries a live revocation.

use entity_ecf::{to_ecf, Value};
use entity_hash::Hash;

use crate::types::{EncryptionError, TYPE_ENCRYPTION_HANDOFF, TYPE_ENCRYPTION_REVOCATION};

/// §10.1 Tier-A rotation handoff. Dual-signed (old + new pubkey holders) at the
/// V7 invariant pointer `system/signature/{hex(handoff_hash)}`.
#[derive(Debug, Clone)]
pub struct EncryptionHandoffData {
    pub previous_pubkey: Hash,
    pub next_pubkey: Hash,
    pub created: u64,
}

impl EncryptionHandoffData {
    /// ECF data value; keys sorted length-first by the encoder
    /// (`created` < `next_pubkey` < `previous_pubkey`).
    pub fn to_ecf_value(&self) -> Value {
        Value::Map(vec![
            (Value::Text("previous_pubkey".into()), Value::Bytes(self.previous_pubkey.to_bytes())),
            (Value::Text("next_pubkey".into()), Value::Bytes(self.next_pubkey.to_bytes())),
            (Value::Text("created".into()), Value::Integer(self.created.into())),
        ])
    }

    pub fn content_hash(&self) -> Hash {
        Hash::compute(TYPE_ENCRYPTION_HANDOFF, &to_ecf(&self.to_ecf_value()))
    }
}

/// §11.1 Tier-A revocation. V7-signed by the peer keypair (the trust anchor).
#[derive(Debug, Clone)]
pub struct EncryptionRevocationData {
    pub revokes: Hash,
    pub reason: Option<String>,
    pub created: u64,
}

impl EncryptionRevocationData {
    /// ECF data value. `reason` is omitted when absent (SHOULD-be-absent
    /// optional, matching Go's `omitempty`).
    pub fn to_ecf_value(&self) -> Value {
        let mut entries = vec![
            (Value::Text("revokes".into()), Value::Bytes(self.revokes.to_bytes())),
            (Value::Text("created".into()), Value::Integer(self.created.into())),
        ];
        if let Some(reason) = &self.reason {
            entries.push((Value::Text("reason".into()), Value::Text(reason.clone())));
        }
        Value::Map(entries)
    }

    pub fn content_hash(&self) -> Hash {
        Hash::compute(TYPE_ENCRYPTION_REVOCATION, &to_ecf(&self.to_ecf_value()))
    }
}

/// In-memory view of a recipient's Tier-A encryption namespace — the
/// signature-verified entities a sender enumerated per §4.4 step 3. Used to
/// resolve the current live encryption-pubkey before encrypting.
#[derive(Debug, Default, Clone)]
pub struct TierAView {
    /// Published `system/encryption-pubkey` content_hashes (§4.2.a).
    pub pubkeys: Vec<Hash>,
    /// `system/encryption/handoff` chain links (§10.1).
    pub handoffs: Vec<EncryptionHandoffData>,
    /// `system/encryption/revocation` entries (§11.1).
    pub revocations: Vec<EncryptionRevocationData>,
}

impl TierAView {
    /// Whether `pubkey` carries a live revocation (§11).
    pub fn is_revoked(&self, pubkey: &Hash) -> bool {
        self.revocations.iter().any(|r| &r.revokes == pubkey)
    }

    /// §10 single step: the pubkey that supersedes `pubkey`, or `None` if no
    /// handoff names it as `previous_pubkey`. Tier-A handoff is single-occupant
    /// (one successor per key); multiple handoffs with the same
    /// `previous_pubkey` is malformed and first match wins. Mirrors Go's
    /// `NextInHandoffChain`.
    pub fn next_in_handoff_chain(&self, pubkey: &Hash) -> Option<Hash> {
        self.handoffs
            .iter()
            .find(|h| &h.previous_pubkey == pubkey)
            .map(|h| h.next_pubkey)
    }

    /// §10.1 forward handoff-chain walk: from a known pubkey, follow the most
    /// recent `handoff` whose `previous_pubkey` matches, repeating until no
    /// further handoff exists. The terminal pubkey is the current one. A cycle
    /// (malformed chain) is broken defensively and returns the last node.
    pub fn walk_to_terminal(&self, start: &Hash) -> Hash {
        let mut current = *start;
        let mut seen = vec![current];
        loop {
            // Most recent handoff (highest `created`) advancing from `current`.
            let next = self
                .handoffs
                .iter()
                .filter(|h| h.previous_pubkey == current)
                .max_by_key(|h| h.created)
                .map(|h| h.next_pubkey);
            match next {
                Some(n) if !seen.contains(&n) => {
                    current = n;
                    seen.push(n);
                }
                _ => return current,
            }
        }
    }

    /// §4.4 / §10 / §11 sender-side recipient resolution. Mirrors Go's
    /// `ResolveCurrentRecipient`:
    ///
    /// - **Revocation supersedes everything (§11).** If `start` is revoked, the
    ///   send is refused with `encryption_key_revoked` — a sender does NOT
    ///   silently redirect to a successor; the key the caller named is dead.
    /// - **Handoff walks the chain (§10).** Otherwise follow the single-occupant
    ///   handoff chain to the terminal non-revoked successor. A revoked key at
    ///   ANY hop terminates resolution with `encryption_key_revoked`.
    ///
    /// The walk is bounded by the number of handoff entries; a longer walk
    /// implies a malformed (cyclic) chain and errors rather than looping.
    pub fn resolve_current(&self, start: &Hash) -> Result<Hash, EncryptionError> {
        if self.is_revoked(start) {
            return Err(EncryptionError::KeyRevoked(format!(
                "requested encryption-pubkey {} is revoked",
                hex_hash(start)
            )));
        }
        let mut current = *start;
        for _ in 0..=self.handoffs.len() {
            match self.next_in_handoff_chain(&current) {
                None => return Ok(current),
                Some(next) => {
                    self.check_encryptable(&next)?;
                    current = next;
                }
            }
        }
        Err(EncryptionError::InvalidWrapper(format!(
            "handoff chain from {} exceeded {} steps (cycle?)",
            hex_hash(start),
            self.handoffs.len()
        )))
    }

    /// §11 sender precondition: MUST NOT encrypt to a revoked pubkey.
    pub fn check_encryptable(&self, pubkey: &Hash) -> Result<(), EncryptionError> {
        if self.is_revoked(pubkey) {
            return Err(EncryptionError::KeyRevoked(format!(
                "encryption-pubkey {} has a live revocation",
                hex_hash(pubkey)
            )));
        }
        Ok(())
    }
}

fn hex_hash(h: &Hash) -> String {
    h.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
