//! `current_signer_set` cache (EXTENSION-QUORUM v1.0 §4.2.1).
//!
//! Per-quorum cache. Invalidated on:
//! - Successful local `:update` / `:publish` op for the quorum.
//! - Validated `quorum-update` / `quorum-publish` attestation arrival
//!   (validate-and-accept moment — NOT raw tree-write).
//! - Live revocation arrival targeting a previously-seen quorum self-event.
//!
//! NOT invalidated on:
//! - Failed K-of-N validation.
//! - Raw `tree:put` bypassing handler validation.
//! - Activity on other quorums (per-quorum scope).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use entity_hash::Hash;

#[derive(Debug, Clone)]
pub struct SignerSet {
    pub signers: Vec<Hash>,
    pub threshold: u64,
}

#[derive(Default)]
pub struct SignerSetCache {
    inner: Arc<RwLock<HashMap<Hash, SignerSet>>>,
}

impl SignerSetCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, quorum_id: &Hash) -> Option<SignerSet> {
        self.inner.read().unwrap().get(quorum_id).cloned()
    }

    pub fn put(&self, quorum_id: Hash, set: SignerSet) {
        self.inner.write().unwrap().insert(quorum_id, set);
    }

    pub fn invalidate(&self, quorum_id: &Hash) {
        self.inner.write().unwrap().remove(quorum_id);
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
